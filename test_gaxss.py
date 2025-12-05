"""
GAXSS Test Suite
"""

import unittest
from ga_core import GAXSS_DNA, GAXSS_Mutations, crossover_uniform, mutate_gaxss
from payload_generator import GAXSS_PayloadGenerator
from fitness_calculator import GAXSS_FitnessCalculator


class TestGACore(unittest.TestCase):
    """Test GA core DNA and operators."""

    def test_dna_creation(self):
        closing = [1, 2, 3, 4]
        main = [5, 6, 7, 8, 9, 10]
        mutations = [0, 1, 2]

        dna = GAXSS_DNA(closing, main, mutations)

        self.assertEqual(dna.closing, closing)
        self.assertEqual(dna.main, main)
        self.assertEqual(dna.mutations, mutations)

    def test_dna_copy(self):
        dna1 = GAXSS_DNA([1, 2, 3, 4], [5, 6, 7, 8, 9, 10], [0, 1])
        dna2 = dna1.copy()

        self.assertEqual(dna1.closing, dna2.closing)
        dna2.closing[0] = 99
        self.assertNotEqual(dna1.closing[0], dna2.closing[0])

    def test_crossover(self):
        parent1 = GAXSS_DNA([1, 2, 3, 4], [5, 6, 7, 8, 9, 10], [0])
        parent2 = GAXSS_DNA([11, 12, 13, 14], [15, 16, 17, 18, 19, 20], [1])

        child1, child2 = crossover_uniform(parent1, parent2)

        self.assertEqual(len(child1.closing), 4)
        self.assertEqual(len(child1.main), 6)


class TestPayloadGenerator(unittest.TestCase):
    """Test payload generation."""

    def setUp(self):
        self.generator = GAXSS_PayloadGenerator()

    def test_payload_generation_type3(self):
        dna = GAXSS_DNA([0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [])
        payload = self.generator.generate_payload_type3(dna)

        self.assertIsNotNone(payload)
        self.assertIn('<', payload)
        self.assertIn('>', payload)


class TestFitnessCalculator(unittest.TestCase):
    """Test fitness calculation."""

    def setUp(self):
        self.calculator = GAXSS_FitnessCalculator()

    def test_execution_score(self):
        # Test 1: Script tag only (returns 0.9)
        output1 = '<script>alert(1)</script>'
        ex1 = self.calculator.calculate_ex(output1)
        self.assertEqual(ex1, 0.9)  # ✅ Correct

        # Test 2: Body with event handler (returns 1.0 - highest priority pattern)
        output2 = '<body onload="alert(1)">'
        ex2 = self.calculator.calculate_ex(output2)
        self.assertEqual(ex2, 1.0)  # ✅ Correct (matches on\w+= pattern)
        
        # Test 3: Img with onerror (also returns 1.0 - matches on\w+= pattern)
        output3 = '<img onerror="alert(1)">'
        ex3 = self.calculator.calculate_ex(output3)
        self.assertEqual(ex3, 1.0)  # ✅ Correct (matches on\w+= pattern)

        # Test 4: No indicators (returns 0.0)
        output4 = 'no indicators here'
        ex4 = self.calculator.calculate_ex(output4)
        self.assertEqual(ex4, 0.0)  # ✅ Correct



def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestGACore))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestFitnessCalculator))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "="*70)
    if result.wasSuccessful():
        print("[OK] ALL TESTS PASSED!")
    else:
        print("[ERROR] SOME TESTS FAILED")
    print("="*70)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
