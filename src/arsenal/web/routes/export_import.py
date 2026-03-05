import sqlite3
import tempfile
import time
import subprocess
import os
import shutil
import ipaddress
import json
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from arsenal.core.parsers.nmap_parser import NmapXMLParser
from arsenal.core.parsers.vulnerability_parser import VulnerabilityParser
from arsenal.web.core.models import Neo4jConfig
from arsenal.web.core.deps import storage

router = APIRouter()

# Añadir check_dependencies si es usado
from arsenal.scripts.check_env import check_dependencies

