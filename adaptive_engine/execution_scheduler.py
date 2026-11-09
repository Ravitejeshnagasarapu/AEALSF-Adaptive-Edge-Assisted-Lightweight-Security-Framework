from __future__ import annotations
import heapq
import time
from dataclasses import dataclass, field
from typing import List, Tuple

from adaptive_engine.decision_engine import AdaptiveDecisionEngine, DecisionRecord
from adaptive_engine.resource_analyzer import (
    DeviceResourceSnapshot,
    TaskRequirementProfile,
)


PRIORITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "NORMAL": 2,
    "LOW": 3,
}


@dataclass(order=True)
class PrioritizedTaskItem:
    priority_rank: int
    created_at: float
    snapshot: DeviceResourceSnapshot = field(compare=False)
    task: TaskRequirementProfile = field(compare=False)


class AdaptiveExecutionScheduler:

    def __init__(self, decision_engine: AdaptiveDecisionEngine) -> None:
        self.decision_engine = decision_engine
        self._queue: List[PrioritizedTaskItem] = []

    def enqueue_task(
        self, snapshot: DeviceResourceSnapshot, task: TaskRequirementProfile
    ) -> None:
        rank = PRIORITY_RANK.get(task.priority, 2)
        heapq.heappush(
            self._queue,
            PrioritizedTaskItem(
                priority_rank=rank,
                created_at=time.time(),
                snapshot=snapshot,
                task=task,
            ),
        )

    def schedule_next(
        self,
    ) -> Tuple[DeviceResourceSnapshot, TaskRequirementProfile, DecisionRecord]:
        if not self._queue:
            raise IndexError("AdaptiveExecutionScheduler queue is empty.")
        item = heapq.heappop(self._queue)
        decision = self.decision_engine.select_execution_mode(item.snapshot, item.task)
        return item.snapshot, item.task, decision

    def pending_count(self) -> int:
        return len(self._queue)
