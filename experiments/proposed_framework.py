from __future__ import annotations
from typing import Dict

from experiments.baseline import (
    create_seeded_fleet_runtime,
    execute_policy_trial_on_fleet,
)


def run_proposed_trial(
    num_devices: int,
    trial_index: int = 0,
    active_task_sample_size: int = 4,
    scheduling_policy: str = "PROPOSED_AEALSF",
) -> Dict[str, object]:
    rt, cohort = create_seeded_fleet_runtime(num_devices, active_cohort_size=6)
    return execute_policy_trial_on_fleet(
        rt, cohort, scheduling_policy, num_devices, trial_index, active_task_sample_size
    )
