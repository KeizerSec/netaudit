# Ce fichier est conservé pour compatibilité ascendante.
# Le code source se trouve dans src/webapp.py
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from webapp import app  # noqa: F401
