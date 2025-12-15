import unittest
from unittest.mock import Mock, patch
from sqlalchemy.orm import Session
from ..interfaces import disassociate_artifact_from_benchmark
from ..models import BenchmarkArtifacts


class TestDisassociateArtifactFromBenchmark(unittest.TestCase):
    @patch("sqlalchemy.orm.Session")
    def test_disassociate_artifact_from_benchmark(self, mock_session):
        # Arrange
        mock_association = Mock(spec=BenchmarkArtifacts)
        mock_session.query.return_value.filter.return_value.first.return_value = (
            mock_association
        )
        mock_session.delete.return_value = None
        mock_session.commit.return_value = None

        # Act
        disassociate_artifact_from_benchmark(mock_session, 1, 1)

        # Assert
        mock_session.query.assert_called_once_with(BenchmarkArtifacts)
        mock_session.query.return_value.filter.assert_called_once_with(
            BenchmarkArtifacts.benchmark_id == 1,
            BenchmarkArtifacts.artifact_id == 1,
        )
        mock_session.delete.assert_called_once_with(mock_association)
        mock_session.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
