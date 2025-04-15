import unittest
from unittest.mock import Mock, patch
from sqlalchemy.orm import Session
from ..interfaces import associate_artifact_with_benchmark
from ..models import BenchmarkArtifacts


class TestAssociateArtifactWithBenchmark(unittest.TestCase):
    @patch("sqlalchemy.orm.Session")
    def test_associate_artifact_with_benchmark(self, mock_session):
        # Arrange
        mock_association = Mock(spec=BenchmarkArtifacts)
        mock_session.add.return_value = None
        mock_session.commit.return_value = None

        # Act
        associate_artifact_with_benchmark(mock_session, 1, 1, True)

        # Assert
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
