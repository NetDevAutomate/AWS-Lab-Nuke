from dataclasses import dataclass
from typing import Any
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

@dataclass
class AWSResource:
    resource_id: str
    region: str
    client: Any

    def delete(self) -> bool:
        try:
            self._pre_delete()
            self._perform_delete()
            self._post_delete()
            logger.info(f"Successfully deleted {self.__class__.__name__} {self.resource_id}")
            return True
        except ClientError as e:
            logger.error(f"Failed to delete {self.__class__.__name__} {self.resource_id}: {e}")
            return False

    def _pre_delete(self):
        pass

    def _perform_delete(self):
        raise NotImplementedError

    def _post_delete(self):
        pass
