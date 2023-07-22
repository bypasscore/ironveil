"""
IronVeil Platform Integrity Checks

Validates casino/iGaming platform integrity: RNG fairness testing,
payout rate verification, game logic validation, provably fair
verification, and server seed analysis.
"""

import hashlib
import hmac
import logging
import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ironveil.utils.crypto import (
    analyze_token_entropy,
    verify_hmac_chain,
    detect_weak_prng,
)

logger = logging.getLogger("ironveil.platform.integrity")


@dataclass
class RNGTestResult:
    """Result of a single RNG fairness test."""
    test_name: str
    passed: bool
    p_value: float
    statistic: float
    description: str
    sample_size: int = 0


@dataclass
class PayoutAnalysis:
    """Analysis of game payout rates."""
    game_name: str
    declared_rtp: Optional[float] = None  # Return To Player %
    observed_rtp: float = 0.0
    sample_size: int = 0
    confidence_interval: Tuple[float, float] = (0.0, 0.0)
    within_tolerance: bool = True
    deviation_pct: float = 0.0


class RNGTester:
    """Tests the quality and fairness of platform random number generation."""

    def __init__(self, sample_size: int = 10000) -> None:
        self.sample_size = sample_size
        self._results: List[RNGTestResult] = []

    def frequency_test(self, samples: List[int], num_bins: int = 10) -> RNGTestResult:
        """Chi-squared frequency test for uniform distribution."""
        n = len(samples)
        expected = n / num_bins
        counts = Counter()

        bin_width = (max(samples) - min(samples) + 1) / num_bins
        for s in samples:
            bin_idx = min(int((s - min(samples)) / bin_width), num_bins - 1)
            counts[bin_idx] += 1

        chi_sq = sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(num_bins))

        # Approximate p-value using chi-squared distribution
        df = num_bins - 1
        p_value = self._chi2_survival(chi_sq, df)

        result = RNGTestResult(
            test_name="frequency",
            passed=p_value > 0.01,
            p_value=round(p_value, 6),
            statistic=round(chi_sq, 4),
            description="Tests uniform distribution of values across bins",
            sample_size=n,
        )
        self._results.append(result)
        return result

    def runs_test(self, samples: List[int]) -> RNGTestResult:
        """Wald-Wolfowitz runs test for randomness."""
        n = len(samples)
        median = statistics.median(samples)
        binary = [1 if s >= median else 0 for s in samples]

        n1 = sum(binary)
        n0 = n - n1
        if n1 == 0 or n0 == 0:
            return RNGTestResult("runs", False, 0.0, 0.0,
                                 "All values on one side of median", n)

        runs = 1
        for i in range(1, n):
            if binary[i] != binary[i - 1]:
                runs += 1

        expected_runs = (2 * n0 * n1) / n + 1
        variance = (2 * n0 * n1 * (2 * n0 * n1 - n)) / (n * n * (n - 1))
        if variance <= 0:
            return RNGTestResult("runs", False, 0.0, 0.0,
                                 "Insufficient variance", n)

        z = (runs - expected_runs) / math.sqrt(variance)
        p_value = 2 * (1 - self._normal_cdf(abs(z)))

        result = RNGTestResult(
            test_name="runs",
            passed=p_value > 0.01,
            p_value=round(p_value, 6),
            statistic=round(z, 4),
            description="Tests for non-random patterns in sequence",
            sample_size=n,
        )
        self._results.append(result)
        return result

    def serial_correlation_test(self, samples: List[int], lag: int = 1) -> RNGTestResult:
        """Test for serial correlation at a given lag."""
        n = len(samples)
        if n <= lag:
            return RNGTestResult("serial_correlation", False, 0.0, 0.0,
                                 "Insufficient samples for lag", n)

        mean = statistics.mean(samples)
        var = statistics.variance(samples)
        if var == 0:
            return RNGTestResult("serial_correlation", False, 0.0, 0.0,
                                 "Zero variance", n)

        cov = sum(
            (samples[i] - mean) * (samples[i + lag] - mean)
            for i in range(n - lag)
        ) / (n - lag)
        correlation = cov / var

        # For large n, sqrt(n)*r is approximately normal
        z = abs(correlation) * math.sqrt(n)
        p_value = 2 * (1 - self._normal_cdf(z))

        result = RNGTestResult(
            test_name=f"serial_correlation_lag{lag}",
            passed=p_value > 0.01,
            p_value=round(p_value, 6),
            statistic=round(correlation, 6),
            description=f"Tests for correlation between values at lag {lag}",
            sample_size=n,
        )
        self._results.append(result)
        return result

    def gap_test(self, samples: List[int], target: int) -> RNGTestResult:
        """Test the distribution of gaps between occurrences of a target value."""
        gaps: List[int] = []
        current_gap = 0
        for s in samples:
            if s == target:
                gaps.append(current_gap)
                current_gap = 0
            else:
                current_gap += 1

        if len(gaps) < 10:
            return RNGTestResult("gap", False, 0.0, 0.0,
                                 "Too few occurrences of target value", len(samples))

        # Expected gap length for uniform distribution
        mean_gap = statistics.mean(gaps)
        expected_gap = len(set(samples)) - 1  # roughly

        # Simple z-test on mean gap length
        std_gap = statistics.stdev(gaps) if len(gaps) >= 2 else 1.0
        z = (mean_gap - expected_gap) / (std_gap / math.sqrt(len(gaps)))
        p_value = 2 * (1 - self._normal_cdf(abs(z)))

        result = RNGTestResult(
            test_name="gap",
            passed=p_value > 0.01,
            p_value=round(p_value, 6),
            statistic=round(z, 4),
            description=f"Tests gap distribution for target value {target}",
            sample_size=len(samples),
        )
        self._results.append(result)
        return result

    def run_all_tests(self, samples: List[int]) -> List[RNGTestResult]:
        """Run the full RNG test suite."""
        self._results.clear()
        self.frequency_test(samples)
        self.runs_test(samples)
        self.serial_correlation_test(samples, lag=1)
        self.serial_correlation_test(samples, lag=2)
        if samples:
            self.gap_test(samples, samples[0])

        passed = sum(1 for r in self._results if r.passed)
        logger.info("RNG tests: %d/%d passed", passed, len(self._results))
        return list(self._results)

    @staticmethod
    def _normal_cdf(x: float) -> float:
        return 0.5 * (1 + math.erf(x / math.sqrt(2)))

    @staticmethod
    def _chi2_survival(x: float, df: int) -> float:
        """Approximate chi-squared survival function."""
        if df <= 0 or x < 0:
            return 1.0
        k = df / 2.0
        return 1.0 - RNGTester._regularized_gamma(k, x / 2.0)

    @staticmethod
    def _regularized_gamma(a: float, x: float, iterations: int = 200) -> float:
        """Regularized lower incomplete gamma via series expansion."""
        if x < 0:
            return 0.0
        if x == 0:
            return 0.0
        total = 0.0
        term = 1.0 / a
        total = term
        for n in range(1, iterations):
            term *= x / (a + n)
            total += term
            if abs(term) < 1e-12:
                break
        return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


class PayoutVerifier:
    """Verifies that game payouts match declared RTP values."""

    def __init__(self, tolerance_pct: float = 2.0) -> None:
        self.tolerance = tolerance_pct
        self._analyses: List[PayoutAnalysis] = []

    def analyze_game(
        self,
        game_name: str,
        bets: List[float],
        payouts: List[float],
        declared_rtp: Optional[float] = None,
    ) -> PayoutAnalysis:
        """Analyze payout data for a single game."""
        if not bets or not payouts or len(bets) != len(payouts):
            raise ValueError("bets and payouts must be non-empty and equal length")

        total_wagered = sum(bets)
        total_returned = sum(payouts)
        observed_rtp = (total_returned / total_wagered * 100) if total_wagered > 0 else 0.0

        # Confidence interval (normal approximation)
        n = len(bets)
        ratios = [p / b * 100 if b > 0 else 0 for b, p in zip(bets, payouts)]
        std_rtp = statistics.stdev(ratios) if n >= 2 else 0
        margin = 1.96 * std_rtp / math.sqrt(n) if n > 0 else 0
        ci = (observed_rtp - margin, observed_rtp + margin)

        within_tol = True
        deviation = 0.0
        if declared_rtp is not None:
            deviation = abs(observed_rtp - declared_rtp)
            within_tol = deviation <= self.tolerance

        analysis = PayoutAnalysis(
            game_name=game_name,
            declared_rtp=declared_rtp,
            observed_rtp=round(observed_rtp, 2),
            sample_size=n,
            confidence_interval=(round(ci[0], 2), round(ci[1], 2)),
            within_tolerance=within_tol,
            deviation_pct=round(deviation, 2),
        )
        self._analyses.append(analysis)
        logger.info("Game %s: observed RTP=%.2f%%, declared=%.2f%%, within_tol=%s",
                     game_name, observed_rtp, declared_rtp or 0, within_tol)
        return analysis

    @property
    def analyses(self) -> List[PayoutAnalysis]:
        return list(self._analyses)


class ProvablyFairVerifier:
    """Verifies provably fair game implementations."""

    @staticmethod
    def verify_hash_chain(server_seeds: List[str]) -> Dict[str, Any]:
        """Verify that server seeds form a valid hash chain."""
        if len(server_seeds) < 2:
            return {"valid": False, "error": "Need at least 2 seeds"}

        breaks: List[int] = []
        for i in range(len(server_seeds) - 1):
            expected = hashlib.sha256(server_seeds[i + 1].encode()).hexdigest()
            if server_seeds[i] != expected:
                breaks.append(i)

        return {
            "valid": len(breaks) == 0,
            "chain_length": len(server_seeds),
            "breaks_at": breaks,
        }

    @staticmethod
    def verify_game_result(
        server_seed: str,
        client_seed: str,
        nonce: int,
        expected_result: Any,
        algorithm: str = "hmac_sha256",
    ) -> Dict[str, Any]:
        """Verify a single game result against its seeds."""
        message = f"{client_seed}:{nonce}"

        if algorithm == "hmac_sha256":
            computed = hmac.new(
                server_seed.encode(), message.encode(), hashlib.sha256
            ).hexdigest()
        elif algorithm == "hmac_sha512":
            computed = hmac.new(
                server_seed.encode(), message.encode(), hashlib.sha512
            ).hexdigest()
        else:
            return {"valid": False, "error": f"Unknown algorithm: {algorithm}"}

        return {
            "valid": True,
            "computed_hash": computed,
            "server_seed": server_seed,
            "client_seed": client_seed,
            "nonce": nonce,
            "algorithm": algorithm,
        }


class IntegrityChecker:
    """Orchestrates all platform integrity checks."""

    def __init__(self, rng_sample_size: int = 10000) -> None:
        self.rng_tester = RNGTester(rng_sample_size)
        self.payout_verifier = PayoutVerifier()
        self.provably_fair = ProvablyFairVerifier()

    def full_check(
        self,
        rng_samples: Optional[List[int]] = None,
        game_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run all integrity checks."""
        results: Dict[str, Any] = {}

        if rng_samples:
            rng_results = self.rng_tester.run_all_tests(rng_samples)
            results["rng"] = {
                "tests_run": len(rng_results),
                "tests_passed": sum(1 for r in rng_results if r.passed),
                "results": [
                    {"test": r.test_name, "passed": r.passed, "p_value": r.p_value}
                    for r in rng_results
                ],
            }

            # Token entropy analysis
            hex_samples = [format(s, "x") for s in rng_samples[:100]]
            entropy_info = analyze_token_entropy("".join(hex_samples))
            results["entropy"] = entropy_info

            # Weak PRNG check
            results["weak_prng"] = detect_weak_prng(rng_samples[:1000])

        if game_data:
            for game in game_data:
                self.payout_verifier.analyze_game(
                    game_name=game["name"],
                    bets=game["bets"],
                    payouts=game["payouts"],
                    declared_rtp=game.get("declared_rtp"),
                )
            results["payouts"] = [
                {
                    "game": a.game_name,
                    "observed_rtp": a.observed_rtp,
                    "declared_rtp": a.declared_rtp,
                    "within_tolerance": a.within_tolerance,
                }
                for a in self.payout_verifier.analyses
            ]

        return results
