#Secure File Encryption v2.3 
# future update:
#   - UTF-16
#   - Performance

import json
import random
import sys
import os
import base64
import hashlib
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import getpass


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Configuration settings for the encryption system."""
    debug: bool = True
    password: str = "passwort"  # System password 
    kdf_iterations: int = 100_000
    salt_size: int = 16
    file_extension: str = ".scff"
    mapping_extension: str = ".enc"
    
    # Character sets for encoding
    alphabet: List[str] = None #type: ignore
    encryption_chars: List[str] = None #type: ignore
    
    # File markers
    marker_start: str = "⡇"
    marker_separator: str = "⡆"
    marker_password: str = "⡈" 
    
    def __post_init__(self):
        if self.alphabet is None:
            self.alphabet = (
                [chr(i) for i in range(32, 217)] + 
                ['\n', '\t', 'ü', 'ä', 'ö', 'ß']
            )
        
        if self.encryption_chars is None:
            self.encryption_chars = list(
                "𒀀𒀁𒀂𒀃𒀄𒀅𒀆𒀇𒀈𒀉𒀊𒀋𒀌𒀍𒀎𒀏𒀐𒀑𒀒𒀓𒀔𒀕𒀖𒀗𒀘𒀙𒀚𒀛𒀜𒀝𒀞𒀟𒀠𒀡𒀢𒀣𒀤𒀥𒀦𒀧𒀨𒀩𒀪𒀫𒀬𒀭𒀮𒀯𒀰𒀱𒀲𒀳𒀴𒀵𒀶𒀷𒀸𒀹𒀺𒀻𒀼𒀽𒀾𒀿𒁀𒁁𒁂𒁃𒁄𒁅𒁆𒁇𒁈𒁉𒁊𒁋𒁌𒁍𒁎𒁏𒁐𒁑𒁒𒁓𒁔𒁕𒁖𒁗𒁘𒁙𒁚𒁛𒁜𒁝𒁞𒁟𒁠𒁡𒁢𒁣𒁤𒁥𒁦𒁧𒁨𒁩𒁪𒁫𒁬𒁭𒁮𒁯𒁰𒁱𒁲𒁳𒁴𒁵𒁶𒁷𒁸𒁹𒁺𒁻𒁼𒁽𒁾𒁿𒂀𒂁𒂂𒂃𒂄𒂅𒂆𒂇𒂈𒂉𒂊𒂋𒂌𒂍𒂎𒂏𒂐𒂑𒂒𒂓𒂔𒂕𒂖𒂗𒂘𒂙𒂚𒂛𒂜𒂝𒂞𒂟𒂠𒂡𒂢𒂣𒂤𒂥𒂦𒂧𒂨𒂩𒂪𒂫𒂬𒂭𒂮𒂯𒂰𒂱𒂲𒂳𒂴𒂵𒂶𒂷𒂸𒂹𒂺𒂻𒂼𒂽𒂾𒂿𒃀𒃁𒃂𒃃𒃄𒃅𒃆𒃇𒃈𒃉𒃊𒃋𒃌𒃍𒃎𒃏𒃐𒃑𒃒𒃓𒃔𒃕𒃖𒃗𒃘𒃙𒃚𒃛𒃜𒃝𒃞𒃟𒃠𒃡𒃢𒃣𒃤𒃥𒃦𒃧𒃨𒃩𒃪𒃫𒃬𒃭𒃮𒃯𒃰𒃱𒃲𒃳𒃴𒃵𒃶𒃷𒃸𒃹𒃺𒃻𒃼𒃽𒃾𒃿𒄀𒄁𒄂𒄃𒄄𒄅𒄆𒄇𒄈𒄉𒄊𒄋𒄌𒄍𒄎𒄏𒄐𒄑𒄒𒄓𒄔𒄕𒄖𒄗𒄘𒄙𒄚𒄛𒄜𒄝𒄞𒄟𒄠𒄡𒄢𒄣𒄤𒄥𒄦𒄧𒄨𒄩𒄪𒄫𒄬𒄭𒄮𒄯𒄰𒄱𒄲𒄳𒄴𒄵𒄶𒄷𒄸𒄹𒄺𒄻𒄼𒄽𒄾𒄿𒅀𒅁𒅂𒅃𒅄𒅅𒅆𒅇𒅈𒅉𒅊𒅋𒅌𒅍𒅎𒅏𒅐𒅑𒅒𒅓𒅔𒅕𒅖𒅗𒅘𒅙𒅚𒅛𒅜𒅝𒅞𒅟𒅠𒅡𒅢𒅣𒅤𒅥𒅦𒅧𒅨𒅩𒅪𒅫𒅬𒅭𒅮𒅯𒅰𒅱𒅲𒅳𒅴𒅵𒅶𒅷𒅸𒅹𒅺𒅻𒅼𒅽𒅾𒅿𒆀𒆁𒆂𒆃𒆄𒆅𒆆𒆇𒆈𒆉𒆊𒆋𒆌𒆍𒆎𒆏𒆐𒆑𒆒𒆓𒆔𒆕𒆖𒆗𒆘𒆙𒆚𒆛𒆜𒆝𒆞𒆟𒆠𒆡𒆢𒆣𒆤𒆥𒆦𒆧𒆨𒆩𒆪𒆫𒆬𒆭𒆮𒆯𒆰𒆱𒆲𒆳𒆴𒆵𒆶𒆷𒆸𒆹𒆺𒆻𒆼𒆽𒆾𒆿𒇀𒇁𒇂𒇃𒇄𒇅𒇆𒇇𒇈𒇉𒇊𒇋𒇌𒇍𒇎𒇏𒇐𒇑𒇒𒇓𒇔𒇕𒇖𒇗𒇘𒇙𒇚𒇛𒇜𒇝𒇞𒇟𒇠𒇡𒇢𒇣𒇤𒇥𒇦𒇧𒇨𒇩𒇪𒇫𒇬𒇭𒇮𒇯𒇰𒇱𒇲𒇳𒇴𒇵𒇶𒇷𒇸𒇹𒇺𒇻𒇼𒇽𒇾𒇿𒈀𒈁𒈂𒈃𒈄𒈅𒈆𒈇𒈈𒈉𒈊𒈋𒈌𒈍𒈎𒈏𒈐𒈑𒈒𒈓𒈔𒈕𒈖𒈗𒈘𒈙𒈚𒈛𒈜𒈝𒈞𒈟𒈠𒈡𒈢𒈣𒈤𒈥𒈦𒈧𒈨𒈩𒈪𒈫𒈬𒈭𒈮𒈯𒈰𒈱𒈲𒈳𒈴𒈵𒈶𒈷𒈸𒈹𒈺𒈻𒈼𒈽𒈾𒈿𒉀𒉁𒉂𒉃𒉄𒉅𒉆𒉇𒉈𒉉𒉊𒉋𒉌𒉍𒉎𒉏𒉐𒉑𒉒𒉓𒉔𒉕𒉖𒉗𒉘𒉙𒉚𒉛𒉜𒉝𒉞𒉟𒉠𒉡𒉢𒉣𒉤𒉥𒉦𒉧𒉨𒉩𒉪𒉫𒉬𒉭𒉮𒉯𒉰𒉱𒉲𒉳𒉴𒉵𒉶𒉷𒉸𒉹𒉺𒉻𒉼𒉽𒉾𒉿𒊀𒊁𒊂𒊃𒊄𒊅𒊆𒊇𒊈𒊉𒊊𒊋𒊌𒊍𒊎𒊏𒊐𒊑𒊒𒊓𒊔𒊕𒊖𒊗𒊘𒊙𒊚𒊛𒊜𒊝𒊞𒊟𒊠𒊡𒊢𒊣𒊤𒊥𒊦𒊧𒊨𒊩𒊪𒊫𒊬𒊭𒊮𒊯𒊰𒊱𒊲𒊳𒊴𒊵𒊶𒊷𒊸𒊹𒊺𒊻𒊼𒊽𒊾𒊿𒋀𒋁𒋂𒋃𒋄𒋅𒋆𒋇𒋈𒋉𒋊𒋋𒋌𒋍𒋎𒋏𒋐𒋑𒋒𒋓𒋔𒋕𒋖𒋗𒋘𒋙𒋚𒋛𒋜𒋝𒋞𒋟𒋠𒋡𒋢𒋣𒋤𒋥𒋦𒋧𒋨𒋩𒋪𒋫𒋬𒋭𒋮𒋯𒋰𒋱𒋲𒋳𒋴𒋵𒋶𒋷𒋸𒋹𒋺𒋻𒋼𒋽𒋾𒋿𒌀𒌁𒌂𒌃𒌄𒌅𒌆𒌇𒌈𒌉𒌊𒌋𒌌𒌍𒌎𒌏𒌐𒌑𒌒𒌓𒌔𒌕𒌖𒌗𒌘𒌙𒌚𒌛𒌜𒌝𒌞𒌟𒌠𒌡𒌢𒌣𒌤𒌥𒌦𒌧𒌨𒌩𒌪𒌫𒌬𒌭𒌮𒌯𒌰𒌱𒌲𒌳𒌴𒌵𒌶𒌷𒌸𒌹𒌺𒌻𒌼𒌽𒌾𒌿𒍀𒍁𒍂𒍃𒍄𒍅𒍆𒍇𒍈𒍉𒍊𒍋𒍌𒍍𒍎𒍏𒍐𒍑𒍒𒍓𒍔𒍕𒍖𒍗𒍘𒍙𒍚𒍛𒍜𒍝𒍞𒍟𒍠𒍡𒍢𒍣𒍤𒍥𒍦𒍧𒍨𒍩𒍪𒍫𒍬𒍭𒍮𒍯𒍰𒍱𒍲𒍳𒍴𒍵𒍶𒍷𒍸𒍹𒍺𒍻𒍼𒍽𒍾𒍿𒎀𒎁𒎂𒎃𒎄𒎅𒎆𒎇𒎈𒎉𒎊𒎋𒎌𒎍𒎎𒎏𒎐𒎑𒎒𒎓𒎔𒎕𒎖𒎗𒎘𒎙𐂀𐂁𐂂𐂃𐂄𐂅𐂆𐂇𐂈𐂉𐂊𐂋𐂌𐂍𐂎𐂏𐂐𐂑𐂒𐂓𐂔𐂕𐂖𐂗𐂘𐂙𐂚𐂛𐂜𐂝𐂞𐂟𐂠𐂡𐂢𐂣𐂤𐂥𐂦𐂧𐂨𐂩𐂪𐂫𐂬𐂭𐂮𐂯𐂰𐂱𐂲𐂳𐂴𐂵𐂶𐂷𐂸𐂹𐂺𐂻𐂼𐂽𐂾𐂿𐃀𐃁𐃂𐃃𐃄𐃅𐃆𐃇𐃈𐃉𐃊𐃋𐃌𐃍𐃎𐃏𐃐𐃑𐃒𐃓𐃔𐃕𐃖𐃗𐃘𐃙𐃚𐃛𐃜𐃝𐃞𐃟𐃠𐃡𐃢𐃣𐃤𐃥𐃦𐃧𐃨𐃩𐃪𐃫𐃬𐃭𐃮𐃯𐃰𐃱𐃲𐃳𐃴𐃵𐃶𐃷𐃸𐃹𐃺𐤀𐤁𐤂𐤃𐤄𐤅𐤆𐤇𐤈𐤉𐤊𐤋𐤌𐤍𐤎𐤏𐤐𐤑𐤒𐤓𐤖𐤗𐤘𐤙𐤚𐤛𐤟𐠀𐠁𐠂𐠃𐠄𐠅𐠈𐠊𐠋𐠌𐠍𐠎𐠏𐠐𐠑𐠒𐠓𐠔𐠕𐠖𐠗𐠘𐠙𐠚𐠛𐠜𐠝𐠞𐠟𐠠𐠡𐠢𐠣𐠤𐠥𐠦𐠧𐠨𐠩𐠪𐠫𐠬𐠭𐠮𐠯𐠰𐠱𐠲𐠳𐠴𐠵𐠷𐠸𐠼𐠿𓀀𓀁𓀂𓀃𓀄𓀅𓀆𓀇𓀈𓀉𓀊𓀋𓀌𓀍𓀎𓀏𓀐𓀑𓀒𓀓𓀔𓀕𓀖𓀗𓀘𓀙𓀚𓀛𓀜𓀝𓀞𓀟𓀠𓀡𓀢𓀣𓀤𓀥𓀦𓀧𓀨𓀩𓀪𓀫𓀬𓀭𓀮𓀯𓀰𓀱𓀲𓀳𓀴𓀵𓀶𓀷𓀸𓀹𓀺𓀻𓀼𓀽𓀾𓀿𓁀𓁁𓁂𓁃𓁄𓁅𓁆𓁇𓁈𓁉𓁊𓁋𓁌𓁍𓁎𓁏𓁐𓁑𓁒𓁓𓁔𓁕𓁖𓁗𓁘𓁙𓁚𓁛𓁜𓁝𓁞𓁟𓁠𓁡𓁢𓁣𓁤𓁥𓁦𓁧𓁨𓁩𓁪𓁫𓁬𓁭𓁮𓁯𓁰𓁱𓁲𓁳𓁴𓁵𓁶𓁷𓁸𓁹𓁺𓁻𓁼𓁽𓁾𓁿𓂀𓂁𓂂𓂃𓂄𓂅𓂆𓂇𓂈𓂉𓂊𓂋𓂌𓂍𓂎𓂏𓂐𓂑𓂒𓂓𓂔𓂕𓂖𓂗𓂘𓂙𓂚𓂛𓂜𓂝𓂞𓂟𓂠𓂡𓂢𓂣𓂤𓂥𓂦𓂧𓂨𓂩𓂪𓂫𓂬𓂭𓂮𓂯𓂰𓂱𓂲𓂳𓂴𓂵𓂶𓂷𓂸𓂺𓂻𓂼𓂽𓂾𓂿𓃀𓃁𓃂𓃃𓃄𓃅𓃆𓃇𓃈𓃉𓃊𓃋𓃌𓃍𓃎𓃏𓃐𓃑𓃒𓃓𓃔𓃕𓃖𓃗𓃘𓃙𓃚𓃛𓃜𓃝𓃞𓃟𓃠𓃡𓃢𓃣𓃤𓃥𓃦𓃧𓃨𓃩𓃪𓃫𓃬𓃭𓃮𓃯𓃰𓃱𓃲𓃳𓃴𓃵𓃶𓃷𓃸𓃹𓃺𓃻𓃼𓃽𓃾𓃿𓄀𓄁𓄂𓄃𓄄𓄅𓄆𓄇𓄈𓄉𓄊𓄋𓄌𓄍𓄎𓄏𓄐𓄑𓄒𓄓𓄔𓄕𓄖𓄗𓄘𓄙𓄚𓄛𓄜𓄝𓄞𓄟𓄠𓄡𓄢𓄣𓄤𓄥𓄦𓄧𓄨𓄩𓄪𓄫𓄬𓄭𓄮𓄯𓄰𓄱𓄲𓄳𓄴𓄵𓄶𓄷𓄸𓄹𓄺𓄻𓄼𓄽𓄾𓄿𓅀𓅁𓅂𓅃𓅄𓅅𓅆𓅇𓅈𓅉𓅊𓅋𓅌𓅍𓅎𓅏𓅐𓅑𓅒𓅓𓅔𓅕𓅖𓅗𓅘𓅙𓅚𓅛𓅜𓅝𓅞𓅟𓅠𓅡𓅢𓅣𓅤𓅥𓅦𓅧𓅨𓅩𓅪𓅫𓅬𓅭𓅮𓅯𓅰𓅱𓅲𓅳𓅴𓅵𓅶𓅷𓅸𓅹𓅺𓅻𓅼𓅽𓅾𓅿𓆀𓆁𓆂𓆃𓆄𓆅𓆆𓆇𓆈𓆉𓆊𓆋𓆌𓆍𓆎𓆏𓆐𓆑𓆒𓆓𓆔𓆕𓆖𓆗𓆘𓆙𓆚𓆛𓆜𓆝𓆞𓆟𓆠𓆡𓆢𓆣𓆤𓆥𓆦𓆧𓆨𓆩𓆪𓆫𓆬𓆭𓆮𓆯𓆰𓆱𓆲𓆳𓆴𓆵𓆶𓆷𓆸𓆹𓆺𓆻𓆼𓆽𓆾𓆿𓇀𓇁𓇂𓇃𓇄𓇅𓇆𓇇𓇈𓇉𓇊𓇋𓇌𓇍𓇎𓇏𓇐𓇑𓇒𓇓𓇔𓇕𓇖𓇗𓇘𓇙𓇚𓇛𓇜𓇝𓇞𓇟𓇠𓇡𓇢𓇣𓇤𓇥𓇦𓇧𓇨𓇩𓇪𓇫𓇬𓇭𓇮𓇯𓇰𓇱𓇲𓇳𓇴𓇵𓇶𓇷𓇸𓇹𓇺𓇻𓇼𓇽𓇾𓇿𓈀𓈁𓈂𓈃𓈄𓈅𓈆𓈇𓈈𓈉𓈊𓈋𓈌𓈍𓈎𓈏𓈐𓈑𓈒𓈓𓈔𓈕𓈖𓈗𓈘𓈙𓈚𓈛𓈜𓈝𓈞𓈟𓈠𓈡𓈢𓈣𓈤𓈥𓈦𓈧𓈨𓈩𓈪𓈫𓈬𓈭𓈮𓈯𓈰𓈱𓈲𓈳𓈴𓈵𓈶U𓈷𓈸𓈹𓈺𓈻𓈼𓈽𓈾𓈿𓉀𓉁𓉂𓉃𓉄𓉅𓉆𓉇𓉈𓉉𓉊𓉋𓉌𓉍𓉎𓉏𓉐𓉑𓉒𓉓𓉔𓉕𓉖𓉗𓉘𓉙𓉚𓉛𓉜𓉝𓉞𓉟𓉠𓉡𓉢𓉣𓉤𓉥𓉦𓉧𓉨𓉩𓉪𓉫𓉬𓉭𓉮𓉯𓉰𓉱𓉲𓉳𓉴𓉵𓉶𓉷𓉸𓉹𓉺𓉻𓉼𓉽𓉾𓉿𓊀𓊁𓊂𓊃𓊄𓊅𓊆𓊇𓊈𓊉𓊊𓊋𓊌𓊍𓊎𓊏𓊐𓊑𓊒𓊓𓊔𓊕𓊖𓊗𓊘𓊙𓊚𓊛𓊜𓊝𓊞𓊟𓊠𓊡𓊢𓊣𓊤𓊥𓊦𓊧𓊨𓊩𓊪𓊫𓊬𓊭𓊮𓊯𓊰𓊱𓊲𓊳𓊴𓊵𓊶𓊷𓊸𓊹𓊺𓊻𓊼𓊽𓊾𓊿𓋀𓋁𓋂𓋃𓋄𓋅𓋆𓋇𓋈𓋉𓋊𓋋𓋌𓋍𓋎𓋏𓋐𓋑𓋒𓋓𓋔𓋕𓋖𓋗𓋘𓋙𓋚𓋛𓋜𓋝𓋞𓋟𓋠𓋡𓋢𓋣𓋤𓋥𓋦𓋧𓋨𓋩𓋪𓋫𓋬𓋭𓋮𓋯𓋰𓋱𓋲𓋳𓋴𓋵𓋶𓋷𓋸𓋹𓋺𓋻𓋼𓋽𓋾𓋿𓌀𓌁𓌂𓌃𓌄𓌅𓌆𓌇𓌈𓌉𓌊𓌋𓌌𓌍𓌎𓌏𓌐𓌑𓌒𓌓𓌔𓌕𓌖𓌗𓌘𓌙𓌚𓌛𓌜𓌝𓌞𓌟𓌠𓌡𓌢𓌣𓌤𓌥𓌦𓌧𓌨𓌩𓌪𓌫𓌬𓌭𓌮𓌯𓌰𓌱𓌲𓌳𓌴𓌵𓌶𓌷𓌸𓌹𓌺𓌻𓌼𓌽𓌾𓌿𓍀𓍁𓍂𓍃𓍄𓍅𓍆𓍇𓍈𓍉𓍊𓍋𓍌𓍍𓍎𓍏𓍐𓍑𓍒𓍓𓍔𓍕𓍖𓍗𓍘𓍙𓍚𓍛𓍜𓍝𓍞𓍟𓍠𓍡𓍢𓍣𓍤𓍥𓍦𓍧𓍨𓍩𓍪𓍫𓍬𓍭𓍮𓍯𓍰𓍱𓍲𓍳𓍴𓍵𓍶𓍷𓍸𓍹𓍺𓍻𓍼𓍽𓍾𓍿𓎀𓎁𓎂𓎃𓎄𓎅𓎆𓎇𓎈𓎉𓎊𓎋𓎌𓎍𓎎𓎏𓎐𓎑𓎒𓎓𓎔𓎕𓎖𓎗𓎘𓎙𓎚𓎛𓎜𓎝𓎞𓎟𓎠𓎡𓎢𓎣𓎤𓎥𓎦𓎧𓎨𓎩𓎪𓎫𓎬𓎭𓎮𓎯𓎰𓎱𓎲𓎳𓎴𓎵𓎶𓎷𓎸𓎹𓎺𓎻𓎼𓎽𓎾𓎿𓏀𓏁𓏂𓏃𓏄𓏅𓏆𓏇𓏈𓏉𓏊𓏋𓏌𓏍𓏎𓏏𓏐𓏑𓏒𓏓𓏔𓏕𓏖𓏗𓏘𓏙𓏚𓏛𓏜Y𓏝𓏞𓏟𓏠𓏡𓏢𓏣𓏤𓏥𓏦𓏧𓏨𓏩𓏪𓏫𓏬𓏭𓏮𓏯𓏰𓏱𓏲𓏳𓏴𓏵𓏶𓏷𓏸𓏹𓏺𓏻𓏽𓏾𓏿𓐀𓐁𓐂𓐃𓐄𓐅𓐆𓐇𓐈𓐉𓐊𓐋𓐌𓐍𓐎𓐏𓐐𓐑𓐒𓐓𓐔𓐕𓐖𓐗𓐘𓐙𓐚𓐛𓐜𓐝𓐞𓐟𓐠𓐡𓐢𓐣𓐤𓐥𓐦𓐧𓐨𓐩𓐪𓐫𓐬𓐭𓐮🜀🜁🜂🜃🜄🜅🜆🜇🜈🜉🜊🜋🜌🜍🜎🜏🜐🜑🜒🜓🜔🜕🜖🜗🜘🜙🜚🜛🜜🜝🜞🜟🜠🜡🜢🜣🜤🜥🜦🜧🜨🜩🜪🜫🜬🜭🜮🜯🜰🜱🜲🜳🜴🜵🜶🜷🜸🜹🜺🜻🜼🜽🜾🜿🝀🝁🝂🝃🝄🝅🝆🝇🝈🝉🝊🝋🝍🝎🝏🝐🝑🝒🝓🝔🝕🝖🝗🝘🝙🝚🝛🝜🝝🝞🝟🝠🝡🝢🝣🝤🝥🝦🝧🝩🝪🝫🝬🝭🝮🝯🝰🝱🝲🝳🙪🙫🙬🙭🙮🙯🙰🙱🙲🙳🙴🙵🙶🙷🙸🙹🙺🙻🙼🙽🙾🙿𖠀𖠁𖠂𖠃𖠄𖠅𖠆𖠇𖠈𖠉𖠊𖠋𖠌𖠍𖠎𖠏𖠐𖠑𖠒Q𖠓𖠔𖠕𖠖𖠗𖠘𖠙𖠚𖠛𖠜𖠝𖠞𖠟𖠠𖠡𖠢𖠣𖠤𖠥𖠦𖠧𖠨𖠩𖠪𖠫𖠬𖠭𖠮𖠯𖠰𖠱𖠲𖠳𖠴𖠵𖠶𖠷𖠸𖠹𖠺𖠻𖠼𖠽𖠾𖠿𖡀𖡁𖡂𖡃𖡄𖡅𖡆𖡇𖡈𖡉𖡊𖡋𖡌𖡍𖡎𖡏𖡐𖡑𖡒𖡓𖡔𖡕𖡖𖡗𖡘𖡙𖡚𖡛𖡜𖡝𖡞𖡟𖡠𖡡𖡢𖡣𖡤𖡥𖡦𖡧𖡨𖡩𖡪𖡫𖡬𖡭𖡮𖡯𖡰𖡱𖡲𖡳𖡴𖡵𖡶𖡷𖡸𖡹𖡺𖡻𖡼𖡽𖡾𖡿𖢀𖢁𖢂𖢃𖢄𖢅𖢆𖢇𖢈𖢉𖢊𖢋𖢌𖢍𖢎𖢏𖢐𖢑𖢒𖢓𖢔𖢕𖢖𖢗𖢘𖢙𖢚𖢛𖢜𖢝𖢞𖢟𖢠𖢡𖢢𖢣𖢤𖢥𖢦𖢧𖢨𖢩𖢪𖢫𖢬𖢭𖢮𖢯𖢰𖢱𖢲𖢳𖢴𖢵𖢶𖢷𖢸𖢹𖢺𖢻𖢼𖢽𖢾𖢿𖣀𖣁𖣂𖣃𖣄𖣅𖣆𖣇𖣈𖣉𖣊𖣋𖣌𖣍𖣎𖣏𖣐𖣑𖣒𖣓𖣔𖣕𖣖𖣗𖣘𖣙𖣚𖣛𖣜𖣝𖣞𖣟𖣠𖣡𖣢𖣣𖣤𖣥𖣦𖣧𖣨𖣩𖣪𖣫𖣬𖣭𖣮𖣯𖣰𖣱𖣲𖣳𖣴𖣵𖣶𖣷𖣸𖣹𖣺𖣻𖣼𖣽𖣾𖣿𖤀𖤁𖤂𖤃𖤄𖤅𖤆𖤇𖤈𖤉𖤊𖤋𖤌𖤍𖤎𖤏𖤐𖤑𖤒𖤓𖤔𖤕𖤖𖤗𖤘𖤙𖤚𖤛𖤜𖤝𖤞𖤟𖤠𖤡𖤢𖤣𖤤𖤥𖤦𖤧𖤨𖤩𖤪𖤫𖤬𖤭𖤮𖤯𖤰𖤱𖤲𖤳𖤴𖤵𖤶𖤷𖤸𖤹𖤺𖤻𖤼𖤽𖤾𖤿𖥀𖥁𖥂𖥃𖥄𖥅𖥆𖥇𖥈𖥉𖥊𖥋𖥌𖥍𖥎𖥏𖥐𖥑𖥒𖥓𖥔𖥕𖥖𖥗𖥘𖥙𖥚𖥛𖥜𖥝𖥞𖥟𖥠𖥡𖥢𖥣𖥤𖥥𖥦𖥧𖥨𖥩𖥪𖥫𖥬𖥭𖥮𖥯𖥰𖥱𖥲𖥳𖥴𖥵𖥶𖥷𖥸𖥹𖥺𖥻𖥼𖥽𖥾𖥿𖦀𖦁𖦂𖦃𖦄𖦅𖦆𖦇𖦈𖦉𖦊𖦋𖦌𖦍𖦎𖦏𖦐𖦑𖦒𖦓𖦔𖦕𖦖𖦗𖦘𖦙𖦚𖦛𖦜𖦝𖦞𖦟𖦠𖦡𖦢𖦣𖦤𖦥𖦦𖦧𖦨𖦩𖦪𖦫𖦬𖦭𖦮𖦯𖦰𖦱𖦲𖦳𖦴𖦵𖦶𖦷𖦸𖦹𖦺𖦻𖦼𖦽𖦾𖦿𖧀𖧁𖧂𖧃𖧄𖧅𖧆𖧇𖧈𖧉𖧊𖧋𖧌𖧍𖧎𖧏𖧐𖧑𖧒𖧓𖧔𖧕𖧖𖧗𖧘𖧙𖧚𖧛𖧜𖧝𖧞𖧟𖧠𖧡𖧢𖧣𖧤𖧥𖧦𖧧𖧨𖧩𖧪𖧫𖧬𖧭𖧮𖧯𖧰𖧱𖧲𖧳𖧴𖧵𖧶𖧷𖧸𖧹𖧺𖧻𖧼𖧽𖧾𖧿𖨀𖨁𖨂𖨃𖨄𖨅𖨆𖨇𖨈𖨉𖨊𖨋𖨌𖨍𖨎𖨏𖨐𖨑𖨒𖨓𖨔𖨕𖨖𖨗𖨘𖨙𖨚𖨛𖨜𖨝𖨞𖨟𖨠𖨡𖨢𖨣𖨤𖨥𖨦𖨧𖨨𖨩𖨪𖨫𖨬𖨭𖨮𖨯𖨰𖨱𖨲𖨳𖨴𖨵𖨶𖨷𖨸🂠🂡🂢🂣🂤🂥🂦🂧🂨🂩🂪🂫🂬🂭🂮🂱🂲🂳🂴🂵🂶🂷🂸🂹🂺🂻🂼🂽🂾🂿🃁🃂🃃🃄🃅🃆🃇🃈🃉🃊🃋🃌🃍🃎🃑🃒🃓🃔🃕🃖🃗🃘🃙🃚🃛🃜🃝🃞🃟🃠🃡🃢🃣🃤🃥🃦🃧🃨🃩🃫🃪🃬🃭🃮🃯🃰🃱🃲🃳🃴🃵" + 
                "".join(chr(i) for i in range(0x1F000, 0x1F100))
            )


CONFIG = Config()


# ============================================================================
# PASSWORD UTILITIES
# ============================================================================

class PasswordManager:
    """Handles password hashing and verification."""
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> tuple[str, bytes]: #type: ignore
        """Hash password with salt using SHA-256."""
        if salt is None:
            salt = get_random_bytes(32)
        
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100_000
        )
        
        # Combine salt and hash for storage
        combined = salt + pwd_hash
        hash_str = base64.b64encode(combined).decode('utf-8')
        
        return hash_str, salt
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored hash."""
        try:
            combined = base64.b64decode(stored_hash.encode('utf-8'))
            salt = combined[:32]
            stored_pwd_hash = combined[32:]
            
            pwd_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100_000
            )
            
            return pwd_hash == stored_pwd_hash
        except Exception:
            return False
    
    @staticmethod
    def prompt_password(prompt: str = "Enter password: ") -> str:
        """Securely prompt for password."""
        return getpass.getpass(prompt)


# ============================================================================
# PATH UTILITIES
# ============================================================================

class PathManager:
    """Manages paths for encrypted files and mappings."""
    
    @staticmethod
    def get_secure_base_path() -> Path:
        """Get base path for secure storage."""
        if hasattr(sys, 'real_prefix') or (
            hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
        ):
            base = Path(sys.prefix)
        elif 'VIRTUAL_ENV' in os.environ:
            base = Path(os.environ['VIRTUAL_ENV'])
        else:
            base = Path.cwd()
        
        return base / "Lib" / "site-packages" / "secure_file" / "secure"
    
    @staticmethod
    def get_data_path() -> Path:
        """Get data storage path."""
        return PathManager.get_secure_base_path() / "data"
    
    @staticmethod
    def ensure_path_exists(path: Path) -> None:
        """Create directory if it doesn't exist."""
        path.mkdir(parents=True, exist_ok=True)


# ============================================================================
# FILE OPERATIONS
# ============================================================================

class FileHandler:
    """Handles file I/O operations."""
    
    @staticmethod
    def to_base64(filepath: Path) -> str:
        """Convert file to base64 string."""
        with open(filepath, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    
    @staticmethod
    def from_base64(base64_str: str, output_path: Path) -> None:
        """Write base64 string to file."""
        PathManager.ensure_path_exists(output_path.parent)
        with open(output_path, "wb") as f:
            f.write(base64.b64decode(base64_str.encode("utf-8")))
    
    @staticmethod
    def check_exists(filepath: Path) -> None:
        """Raise error if file doesn't exist."""
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")


# ============================================================================
# CHARACTER MAPPING
# ============================================================================

class CharacterMapper:
    """Handles character encoding/decoding with custom mapping."""
    
    def __init__(self, config: Config):
        self.config = config
    
    def to_charset(self, text: str) -> str:
        """Convert text from alphabet to encryption charset."""
        result = []
        for char in text:
            if char in self.config.alphabet:
                idx = self.config.alphabet.index(char)
                result.append(self.config.encryption_chars[idx])
            else:
                result.append('[UNKNOWN]')
        return ''.join(result)
    
    def from_charset(self, text: str) -> str:
        """Convert text from encryption charset to alphabet."""
        result = []
        for char in text:
            if char in self.config.encryption_chars:
                idx = self.config.encryption_chars.index(char)
                result.append(self.config.alphabet[idx])
            else:
                result.append('[UNKNOWN]')
        return ''.join(result)
    
    def create_random_mapping(self) -> Dict[str, str]:
        """Create randomized character mapping."""
        shuffled = self.config.encryption_chars[:]
        random.shuffle(shuffled)
        return {
            self.config.alphabet[i]: shuffled[i] 
            for i in range(len(self.config.alphabet))
        }
    
    def encode_text(self, text: str, mapping: Dict[str, str]) -> str:
        """Encode text using mapping."""
        return ''.join(mapping.get(c, '[UNKNOWN]') for c in text)
    
    def decode_text(self, text: str, mapping: Dict[str, str]) -> str:
        """Decode text using reverse mapping."""
        reverse = {v: k for k, v in mapping.items()}
        return ''.join(reverse.get(c, '?') for c in text)


# ============================================================================
# ENCRYPTION
# ============================================================================

class Encryptor:
    """Handles AES-GCM encryption operations."""
    
    def __init__(self, config: Config):
        self.config = config
    
    def encrypt_data(self, data: bytes, password: str = None) -> bytes: #type: ignore
        """Encrypt data using AES-GCM."""
        pwd = password if password else self.config.password
        
        salt = get_random_bytes(self.config.salt_size)
        key = PBKDF2(pwd, salt, dkLen=32, count=self.config.kdf_iterations)
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Format: salt + nonce + tag + ciphertext
        return salt + cipher.nonce + tag + ciphertext
    
    def decrypt_data(self, encrypted: bytes, password: str = None) -> bytes: #type: ignore
        """Decrypt data using AES-GCM."""
        pwd = password if password else self.config.password
        
        salt = encrypted[:16]
        nonce = encrypted[16:32]
        tag = encrypted[32:48]
        ciphertext = encrypted[48:]
        
        key = PBKDF2(pwd, salt, dkLen=32, count=self.config.kdf_iterations)
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)


# ============================================================================
# MAPPING STORAGE
# ============================================================================

class MappingStorage:
    """Manages storage of character mappings."""
    
    def __init__(self, config: Config, mapper: CharacterMapper, encryptor: Encryptor):
        self.config = config
        self.mapper = mapper
        self.encryptor = encryptor
    
    def save(self, mapping: Dict[str, str], filename: str) -> Path:
        """Save encrypted mapping to file."""
        # Obfuscate keys
        obfuscated = {
            self.mapper.to_charset(k): v 
            for k, v in mapping.items()
        }
        
        # Convert to JSON
        json_data = json.dumps(obfuscated, ensure_ascii=False).encode('utf-8')
        
        # Encrypt
        encrypted = self.encryptor.encrypt_data(json_data)
        
        # Save
        stem = Path(filename).stem
        output_path = PathManager.get_data_path() / f"{stem}{self.config.mapping_extension}"
        PathManager.ensure_path_exists(output_path.parent)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        
        if self.config.debug:
            print(f"✓ Mapping saved: {output_path}")
        
        return output_path
    
    def load(self, filename: str) -> Dict[str, str]:
        """Load and decrypt mapping from file."""
        stem = Path(filename).stem
        mapping_path = PathManager.get_data_path() / f"{stem}{self.config.mapping_extension}"
        
        with open(mapping_path, 'rb') as f:
            encrypted = f.read()
        
        # Decrypt
        decrypted = self.encryptor.decrypt_data(encrypted)
        obfuscated = json.loads(decrypted.decode('utf-8'))
        
        # Deobfuscate keys
        return {
            self.mapper.from_charset(k): v 
            for k, v in obfuscated.items()
        }


# ============================================================================
# FILE ENCODER
# ============================================================================

class FileEncoder:
    """Encodes files using character mapping."""
    
    def __init__(self, config: Config, mapper: CharacterMapper):
        self.config = config
        self.mapper = mapper
        self.pwd_manager = PasswordManager()
    
    def encode(self, filepath: Path, mapping: Dict[str, str], user_password: Optional[str] = None) -> Path:
        """Encode file and save encrypted version."""
        # Convert to base64
        base64_str = FileHandler.to_base64(filepath)
        
        # Encode path and content
        encoded_path = self.mapper.encode_text(str(filepath.absolute()), mapping)
        encoded_body = self.mapper.encode_text(base64_str, mapping)
        
        
        
        
        #optionales passwort 
        #damit 
        suffix = filepath.suffix
        if user_password:
            # Hash
            pwd_hash, _ = self.pwd_manager.hash_password(user_password)
            encoded_password = self.mapper.encode_text(pwd_hash, mapping)
            
            # Format: ⡇.ext⡆path⡈password⡇body
            output_content = (
                f"{self.config.marker_start}{suffix}"
                f"{self.config.marker_separator}{encoded_path}"
                f"{self.config.marker_password}{encoded_password}"
                f"{self.config.marker_start}{encoded_body}"
            )
            
            if self.config.debug:
                print(f"Password protection enabled")
        else:
            # Format: ⡇.ext⡆path⡇body (no password)
            output_content = (
                f"{self.config.marker_start}{suffix}"
                f"{self.config.marker_separator}{encoded_path}"
                f"{self.config.marker_start}{encoded_body}"
            )
        
        # Save
        output_path = PathManager.get_data_path() / f"{filepath.stem}{self.config.file_extension}"
        PathManager.ensure_path_exists(output_path.parent)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(output_content)
        
        if self.config.debug:
            print(f"✓ File encoded: {output_path}")
        
        return output_path


# ============================================================================
# FILE DECODER
# ============================================================================

class FileDecoder:
    """Decodes encrypted files."""
    
    def __init__(self, config: Config, mapper: CharacterMapper):
        self.config = config
        self.mapper = mapper
        self.pwd_manager = PasswordManager()
    
    def decode(self, encoded_path: Path, mapping: Dict[str, str], user_password: Optional[str] = None) -> Path:
        """Decode encrypted file and restore original."""
        # Read encoded content
        with open(encoded_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse header
        header_info = self._parse_header(content)
        
        # Check password if present
        if header_info['has_password']:
            if not user_password:
                raise PermissionError("This file is password protected. Password required!")
            
            # Decode stored password hash
            reverse_mapping = {v: k for k, v in mapping.items()}
            decoded_hash = ''.join(
                reverse_mapping.get(c, '?') 
                for c in header_info['password']
            )
            
            # Verify password
            if not self.pwd_manager.verify_password(user_password, decoded_hash):
                raise PermissionError("Incorrect password!")
            
            if self.config.debug:
                print(f"✓ Password verified")
        
        # Decode body
        reverse_mapping = {v: k for k, v in mapping.items()}
        decoded_base64 = ''.join(
            reverse_mapping.get(c, '?') 
            for c in header_info['body']
        )
        
        # Fix base64 padding
        decoded_base64 = self._fix_base64_padding(decoded_base64)
        
        # Decode path
        decoded_path = self._decode_path(header_info['path'], reverse_mapping)
        
        # Write file
        output_path = Path(decoded_path)
        FileHandler.from_base64(decoded_base64, output_path)
        
        if self.config.debug:
            print(f"✓ File decoded: {output_path}")
        
        return output_path
    
    def _parse_header(self, content: str) -> Dict:
        """Parse encoded file header with optional password."""
        try:
            # Find all markers
            first = content.index(self.config.marker_start)
            second_start = first + 1
            
            # Check if password marker exists
            has_password = self.config.marker_password in content
            
            if has_password:
                # Format: ⡇.ext⡆path⡈password⡇body
                sep_pos = content.index(self.config.marker_separator, second_start)
                pwd_pos = content.index(self.config.marker_password, sep_pos)
                body_pos = content.index(self.config.marker_start, pwd_pos)
                
                suffix = content[first + 1:sep_pos]
                path = content[sep_pos + 1:pwd_pos]
                password = content[pwd_pos + 1:body_pos]
                body = content[body_pos + 1:]
                
                return {
                    'suffix': suffix,
                    'path': path,
                    'password': password,
                    'body': body,
                    'has_password': True
                }
            else:
                # Format: ⡇.ext⡆path⡇body (no password)
                sep_pos = content.index(self.config.marker_separator, second_start)
                body_pos = content.index(self.config.marker_start, sep_pos)
                
                suffix = content[first + 1:sep_pos]
                path = content[sep_pos + 1:body_pos]
                body = content[body_pos + 1:]
                
                return {
                    'suffix': suffix,
                    'path': path,
                    'password': None,
                    'body': body,
                    'has_password': False
                }
                
        except (ValueError, IndexError) as e:
            raise ValueError(f"Invalid file format: {e}")
    
    def _fix_base64_padding(self, b64: str) -> str:
        """Add missing base64 padding."""
        missing = len(b64) % 4
        if missing:
            return b64 + "=" * (4 - missing)
        return b64
    
    def _decode_path(self, encoded_path: str, reverse_mapping: Dict[str, str]) -> str:
        """Decode file path."""
        try:
            return ''.join(reverse_mapping[c] for c in encoded_path)
        except KeyError as e:
            if self.config.debug:
                print(f"⚠ Warning: Unknown character in path: {e}")
            return str(PathManager.get_data_path())


# ============================================================================
# HIGH-LEVEL API
# ============================================================================

class SecureFileManager:
    """High-level interface for file encryption."""
    
    def __init__(self, config: Config = None): #type: ignore
        self.config = config or CONFIG
        self.mapper = CharacterMapper(self.config)
        self.encryptor = Encryptor(self.config)
        self.mapping_storage = MappingStorage(self.config, self.mapper, self.encryptor)
        self.encoder = FileEncoder(self.config, self.mapper)
        self.decoder = FileDecoder(self.config, self.mapper)
        self.pwd_manager = PasswordManager()
    
    def encrypt_file(
        self, 
        filepath: str, 
        password: Optional[str] = None,
        delete_original: bool = False,
        prompt_password: bool = False
    ) -> None:
        """
        Encrypt a single file.
        
        Args:
            filepath: Path to file to encrypt
            password: Optional password for additional protection
            delete_original: Whether to delete original file after encryption
            prompt_password: Whether to prompt user for password interactively
        """
        path = Path(filepath).absolute()
        FileHandler.check_exists(path)
        
        print(f"Encrypting: {path.name}")
        
        # Get password if prompting
        if prompt_password and not password:
            password = self.pwd_manager.prompt_password("Enter password for file (leave empty for none): ")
            if password.strip() == "":
                password = None
            elif password:
                # Confirm password
                confirm = self.pwd_manager.prompt_password("Confirm password: ")
                if password != confirm:
                    print("Passwords don't match!")
                    return
        
        # Create and save mapping
        mapping = self.mapper.create_random_mapping()
        self.mapping_storage.save(mapping, path.name)
        
        # Encode file with optional password
        self.encoder.encode(path, mapping, password)
        
        # Optional: delete original
        if delete_original:
            path.unlink()
            print(f"🗑 Original deleted")
    
    def decrypt_file(
        self, 
        filename: str, 
        password: Optional[str] = None,
        cleanup: bool = False,
        prompt_password: bool = False
    ) -> Path:
        """
        Decrypt a single file.
        
        Args:
            filename: Name of file to decrypt
            password: Optional password if file is protected
            cleanup: Whether to delete encrypted files after decryption
            prompt_password: Whether to prompt user for password if needed
        """
        # Find file
        stem = Path(filename).stem
        encoded_path = PathManager.get_data_path() / f"{stem}{self.config.file_extension}"
        
        if not encoded_path.exists():
            encoded_path = self._find_file(filename)
        
        FileHandler.check_exists(encoded_path)
        
        print(f"Decrypting: {encoded_path.name}")
        
        # Load mapping
        mapping = self.mapping_storage.load(filename)
        
        # Try to decode - will fail if password required
        max_attempts = 3
        attempt = 0
        
        while attempt < max_attempts:
            try:
                output_path = self.decoder.decode(encoded_path, mapping, password)
                break
            except PermissionError as e:
                if "password protected" in str(e).lower() or "incorrect password" in str(e).lower():
                    if prompt_password:
                        attempt += 1
                        if attempt >= max_attempts:
                            print(f"Maximum password attempts reached!")
                            raise
                        password = self.pwd_manager.prompt_password(
                            f"Enter password ({max_attempts - attempt} attempts left): "
                        )
                    else:
                        raise
                else:
                    raise
        
        # Optional: cleanup encrypted files
        if cleanup:
            encoded_path.unlink()
            mapping_path = PathManager.get_data_path() / f"{stem}{self.config.mapping_extension}"
            mapping_path.unlink()
            print(f"🗑 Cleanup completed")
        
        return output_path
    
    
    
    # WARNING!!! NO LONGER MAINTAINED
    def encrypt_folder(
        self, 
        folder_path: str, 
        password: Optional[str] = None,
        delete_originals: bool = False,
        prompt_password: bool = False
    ) -> None:
        """
        Recursively encrypt all files in folder.
        NOT MAINTAINED
        """
        folder = Path(folder_path)
        
        print(f"Encrypting folder: {folder}")
        
        # Get password once if prompting
        if prompt_password and not password:
            password = self.pwd_manager.prompt_password(
                "Enter password): "
            )
            if password.strip() == "":
                password = None
            elif password:
                confirm = self.pwd_manager.prompt_password("Confirm: ")
                if password != confirm:
                    print("Passwords don't match!")
                    return
        
        file_count = 0
        for file_path in folder.rglob('*'):
            if file_path.is_file() and not file_path.suffix == self.config.file_extension:
                try:
                    self.encrypt_file(str(file_path), password, delete_originals, prompt_password=False)
                    file_count += 1
                except Exception as e:
                    print(f"Error: {file_path.name} - {e}")
        
        print(f"✓ Encrypted {file_count} files")
    
    def decrypt_folder(
        self, 
        folder_path: str = None, #type: ignore
        password: Optional[str] = None,
        cleanup: bool = False,
        prompt_password: bool = False
    ) -> None:
        """
        Recursively decrypt all encrypted files.
        
        Args:
            folder_path: Path to folder (defaults to data directory)
            password: Optional password for protected files
            cleanup: Whether to delete encrypted files after decryption
            prompt_password: Whether to prompt for password if needed
        """
        folder = Path(folder_path) if folder_path else PathManager.get_data_path()
        
        print(f"Decrypting folder: {folder}")
        
        file_count = 0
        for file_path in folder.rglob(f'*{self.config.file_extension}'):
            try:
                self.decrypt_file(file_path.stem, password, cleanup, prompt_password)
                file_count += 1
            except Exception as e:
                print(f"❌ Error: {file_path.name} - {e}")
        
        print(f"✓ Decrypted {file_count} files")
    
    def _find_file(self, filename: str) -> Path:
        """Find encrypted file in data directory."""
        stem = Path(filename).stem
        data_path = PathManager.get_data_path()
        
        for file_path in data_path.rglob(f'{stem}{self.config.file_extension}'):
            return file_path
        
        raise FileNotFoundError(f"Encrypted file not found: {filename}")


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

def main():
    """Example usage."""
    manager = SecureFileManager()
    
    # ========== EINZELNE DATEI ==========
    
    # Ohne Passwort
    #manager.encrypt_file("test.txt", delete_original=False)
    #manager.decrypt_file("test.txt", cleanup=False)
    
    # Mit Passwort (direkt angeben)
    #manager.encrypt_file("test.txt", password="123", delete_original=False)
    #manager.decrypt_file("test.txt", password="123", cleanup=False)
    
    # Mit Passwort (im terminal eingeben)
    #manager.encrypt_file("test.txt", prompt_password=True, delete_original=False)
    #manager.decrypt_file("test.txt", prompt_password=True, cleanup=False)
main()