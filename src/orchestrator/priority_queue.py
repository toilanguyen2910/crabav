"""
Priority Task Queue - Manages task scheduling and prioritization
"""

import asyncio
from typing import Any, Dict, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
import heapq

from ..utils import get_logger

logger = get_logger("task_queue")


class TaskPriority(IntEnum):
    """Task priority levels (lower number = higher priority)"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


@dataclass(order=True)
class Task:
    """A prioritized task"""
    priority: int
    task_id: str = field(compare=False)
    callback: Callable[[], Awaitable[Any]] = field(compare=False)
    created_at: datetime = field(default_factory=datetime.now, compare=False)
    metadata: Dict[str, Any] = field(default_factory=dict, compare=False)


class PriorityTaskQueue:
    """
    Priority-based task queue for orchestrator
    
    Features:
    - Priority-based scheduling
    - Async task execution
    - Task cancellation
    - Status tracking
    """
    
    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self._queue: list = []
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._completed_tasks: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._workers: list = []
        self._running = False
        
        logger.info(f"PriorityTaskQueue initialized with {max_workers} workers")
    
    async def start(self) -> None:
        """Start the task queue workers"""
        if self._running:
            return
        
        self._running = True
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.max_workers)
        ]
        logger.info(f"Started {self.max_workers} task workers")
    
    async def stop(self) -> None:
        """Stop the task queue workers"""
        self._running = False
        
        # Cancel all active tasks
        for task_id, task in self._active_tasks.items():
            task.cancel()
            logger.info(f"Cancelled task: {task_id}")
        
        # Wait for workers to finish
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        
        self._workers = []
        logger.info("Task queue stopped")
    
    async def add_task(
        self,
        task_id: str,
        callback: Callable[[], Awaitable[Any]],
        priority: TaskPriority = TaskPriority.NORMAL,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a task to the queue"""
        async with self._lock:
            task = Task(
                priority=priority.value,
                task_id=task_id,
                callback=callback,
                metadata=metadata or {}
            )
            heapq.heappush(self._queue, task)
            logger.info(f"Added task {task_id} with priority {priority.name}")
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a task"""
        if task_id in self._active_tasks:
            self._active_tasks[task_id].cancel()
            logger.info(f"Cancelled active task: {task_id}")
            return True
        
        # Remove from queue if not yet started
        async with self._lock:
            self._queue = [t for t in self._queue if t.task_id != task_id]
            heapq.heapify(self._queue)
            logger.info(f"Removed queued task: {task_id}")
            return True
    
    async def _worker(self, worker_id: int) -> None:
        """Worker that processes tasks from the queue"""
        logger.info(f"Worker {worker_id} started")
        
        while self._running:
            task = await self._get_next_task()
            
            if task is None:
                await asyncio.sleep(0.1)
                continue
            
            try:
                logger.info(f"Worker {worker_id} executing task: {task.task_id}")
                
                # Create async task
                async_task = asyncio.create_task(task.callback())
                self._active_tasks[task.task_id] = async_task
                
                # Execute
                result = await async_task
                
                # Store result
                self._completed_tasks[task.task_id] = {
                    'result': result,
                    'completed_at': datetime.now(),
                    'metadata': task.metadata
                }
                
                logger.info(f"Task {task.task_id} completed successfully")
                
            except asyncio.CancelledError:
                logger.info(f"Task {task.task_id} was cancelled")
            except Exception as e:
                logger.error(f"Task {task.task_id} failed: {e}")
                self._completed_tasks[task.task_id] = {
                    'error': str(e),
                    'completed_at': datetime.now()
                }
            finally:
                # Clean up
                if task.task_id in self._active_tasks:
                    del self._active_tasks[task.task_id]
        
        logger.info(f"Worker {worker_id} stopped")
    
    async def _get_next_task(self) -> Optional[Task]:
        """Get the next task from the queue"""
        async with self._lock:
            if self._queue:
                return heapq.heappop(self._queue)
        return None
    
    def get_queue_size(self) -> int:
        """Get number of tasks waiting in queue"""
        return len(self._queue)
    
    def get_active_count(self) -> int:
        """Get number of currently executing tasks"""
        return len(self._active_tasks)
    
    def get_task_status(self, task_id: str) -> Optional[str]:
        """Get status of a task"""
        if task_id in self._active_tasks:
            return "running"
        if task_id in self._completed_tasks:
            return "completed"
        if any(t.task_id == task_id for t in self._queue):
            return "queued"
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get queue statistics"""
        return {
            'queue_size': self.get_queue_size(),
            'active_tasks': self.get_active_count(),
            'completed_tasks': len(self._completed_tasks),
            'workers': self.max_workers,
            'running': self._running
        }
