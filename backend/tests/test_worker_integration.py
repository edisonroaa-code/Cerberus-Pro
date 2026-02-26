
import unittest
from unittest.mock import MagicMock, patch
import json
from backend.worker.worker import Worker
from backend.scheduler.redis_scheduler import RedisScheduler

class TestWorkerIntegration(unittest.TestCase):

    @patch('redis.from_url')
    def test_scheduler_store_result(self, mock_redis_cls):
        mock_redis = MagicMock()
        mock_redis_cls.return_value = mock_redis
        
        scheduler = RedisScheduler()
        scheduler.store_result("job123", {"status": "ok"})
        
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args
        self.assertIn("cerberus:result:job123", args[0])
        self.assertIn('{"status": "ok"}', args[0])

    @patch('redis.from_url')
    def test_worker_scan_job(self, mock_redis_cls):
        mock_redis = MagicMock()
        mock_redis_cls.return_value = mock_redis
        
        worker = Worker()
        # Mock scheduler inside worker
        worker.scheduler = MagicMock()
        
        job = {
            "id": "job-abc",
            "type": "scan_target",
            "payload": {"target": "http://example.com"}
        }
        
        worker.handle_job(job)
        
        # specific assertions
        worker.scheduler.store_result.assert_called_once()
        call_args = worker.scheduler.store_result.call_args
        job_id, result = call_args[0]
        
        self.assertEqual(job_id, "job-abc")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["findings"][0]["type"], "sql_injection")

if __name__ == '__main__':
    unittest.main()
