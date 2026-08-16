'''
The Model Exporter & Catalog Registry
Why It Exists:
When Python executes code, it only loads files that are explicitly imported. If app/models/user.py or app/models/device.py are never imported into memory, 
Base.metadata will remain empty and won't create those tables in SQLite
Core Logic:

Explicit Imports: Imports User and ManagedDevice so that simply running import app.models automatically registers both tables inside Base.metadata.

__all__: A Python standard variable defining which symbols are publicly exposed when someone writes from app.models import *.

'''

from app.models.compliance import CompliancePolicy
from app.models.device import ManagedDevice
from app.models.script import DeploymentScript
from app.models.user import User

# __all__ = ["User", "ManagedDevice"]
# __all__ = ["ManagedDevice", "User"]
__all__ = ["CompliancePolicy", "DeploymentScript", "ManagedDevice", "User"]