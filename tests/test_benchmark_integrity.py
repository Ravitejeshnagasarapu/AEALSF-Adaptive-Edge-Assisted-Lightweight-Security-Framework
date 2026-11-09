import csv
import json
import os
import statistics
import unittest


class TestBenchmarkAndArtifactIntegrity(unittest.TestCase):
    def test_30_trial_six_way_raw_and_summary_consistency(self) -> None:
        self.assertTrue(os.path.exists("results/benchmark_results.json"))
        self.assertTrue(os.path.exists("results/raw_trials.json"))
        self.assertTrue(os.path.exists("results/raw_trials.csv"))
        self.assertTrue(os.path.exists("AEALSF_Raw_Experimental_Results.csv"))
        self.assertTrue(os.path.exists("AEALSF_Experimental_Summary.csv"))

        with open("results/benchmark_results.json", "r", encoding="utf-8") as f:
            rep = json.load(f)
        with open("results/raw_trials.json", "r", encoding="utf-8") as f:
            raw = json.load(f)

        self.assertEqual(len(raw), 540)
        trial_ids = [r["trial_id"] for r in raw]
        self.assertEqual(
            len(set(trial_ids)), 540, "All 540 trial_id values must be unique"
        )

        six_way = rep["six_way_comparisons_by_device_count"]
        for c_key in ("100", "500", "1000"):
            self.assertEqual(len(six_way[c_key]), 6)
            for pol, ag in six_way[c_key].items():
                self.assertEqual(
                    ag["num_trials"], 30, f"Policy {pol} at {c_key} must have 30 trials"
                )
                self.assertEqual(ag["actual_active_client_count"], int(c_key))
                raw_subset = [
                    float(r["cpu_utilization_pct"])
                    for r in raw
                    if int(r["device_count"]) == int(c_key) and r["policy"] == pol
                ]
                self.assertEqual(len(raw_subset), 30)
                calc_mean = round(statistics.mean(raw_subset), 4)
                self.assertAlmostEqual(
                    calc_mean,
                    float(ag["cpu_utilization_percent"]["mean"]),
                    places=2,
                )
                raw_mem_subset = [
                    float(r["memory_kb"])
                    for r in raw
                    if int(r["device_count"]) == int(c_key) and r["policy"] == pol
                ]
                calc_mem_mean = round(statistics.mean(raw_mem_subset), 4)
                self.assertAlmostEqual(
                    calc_mem_mean,
                    float(ag["memory_consumption_kb"]["mean"]),
                    places=2,
                )

    def test_all_26_graphs_and_16_tables_exist(self) -> None:
        for i in range(1, 27):
            png_files = [
                f
                for f in os.listdir("results/figures")
                if f.startswith(f"graph{i:02d}_") and f.endswith(".png")
            ]
            svg_files = [
                f
                for f in os.listdir("results/figures")
                if f.startswith(f"graph{i:02d}_") and f.endswith(".svg")
            ]
            self.assertGreaterEqual(len(png_files), 1, f"Missing PNG for graph{i:02d}")
            self.assertGreaterEqual(len(svg_files), 1, f"Missing SVG for graph{i:02d}")

        for j in range(1, 17):
            csv_files = [
                f
                for f in os.listdir("results/tables")
                if f.startswith(f"table{j:02d}_") and f.endswith(".csv")
            ]
            md_files = [
                f
                for f in os.listdir("results/tables")
                if f.startswith(f"table{j:02d}_") and f.endswith(".md")
            ]
            self.assertGreaterEqual(len(csv_files), 1, f"Missing CSV for table{j:02d}")
            self.assertGreaterEqual(len(md_files), 1, f"Missing MD for table{j:02d}")


if __name__ == "__main__":
    unittest.main()
