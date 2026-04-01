from backend.modules.sqli          import SQLiModule
from backend.modules.xss           import XSSModule
from backend.modules.ssti          import SSTIModule
from backend.modules.lfi           import LFIModule
from backend.modules.cmdi          import CMDiModule
from backend.modules.jwt           import JWTModule
from backend.modules.ssrf          import SSRFModule
from backend.modules.idor          import IDORModule
from backend.modules.xxe           import XXEModule
from backend.modules.nosql         import NoSQLModule
from backend.modules.open_redirect import OpenRedirectModule
from backend.modules.dirbrute      import DirBruteModule
from backend.modules.headers       import HeadersModule
from backend.modules.typejuggle    import TypeJuggleModule

__all__ = [
    "SQLiModule","XSSModule","SSTIModule","LFIModule","CMDiModule",
    "JWTModule","SSRFModule","IDORModule","XXEModule","NoSQLModule",
    "OpenRedirectModule","DirBruteModule","HeadersModule","TypeJuggleModule",
]
