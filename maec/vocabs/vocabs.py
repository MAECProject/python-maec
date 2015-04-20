from cybox.common import VocabString

class DataTheftTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DataTheftTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'steal dialed phone numbers',
        'steal email data',
        'steal referrer urls',
        'steal cryptocurrency data',
        'steal pki software certificate',
        'steal browser cache',
        'steal serial numbers',
        'steal sms database',
        'steal cookie',
        'steal password hash',
        'steal make/model',
        'steal documents',
        'steal network address',
        'steal open port',
        'steal images',
        'steal browser history',
        'steal web/network credential',
        'steal pki key',
        'steal contact list data',
        'steal database content',
    )
    TERM_STEAL_DIALED_PHONE_NUMBERS = 'steal dialed phone numbers'
    TERM_STEAL_EMAIL_DATA = 'steal email data'
    TERM_STEAL_PKI_KEY = 'steal pki key'
    TERM_STEAL_CRYPTOCURRENCY_DATA = 'steal cryptocurrency data'
    TERM_STEAL_PKI_SOFTWARE_CERTIFICATE = 'steal pki software certificate'
    TERM_STEAL_BROWSER_CACHE = 'steal browser cache'
    TERM_STEAL_SERIAL_NUMBERS = 'steal serial numbers'
    TERM_STEAL_SMS_DATABASE = 'steal sms database'
    TERM_STEAL_COOKIE = 'steal cookie'
    TERM_STEAL_PASSWORD_HASH = 'steal password hash'
    TERM_STEAL_MAKE_MODEL = 'steal make/model'
    TERM_STEAL_DOCUMENTS = 'steal documents'
    TERM_STEAL_CONTACT_LIST_DATA = 'steal contact list data'
    TERM_STEAL_REFERRER_URLS = 'steal referrer urls'
    TERM_STEAL_DATABASE_CONTENT = 'steal database content'
    TERM_STEAL_BROWSER_HISTORY = 'steal browser history'
    TERM_STEAL_WEB_NETWORK_CREDENTIAL = 'steal web/network credential'
    TERM_STEAL_IMAGES = 'steal images'
    TERM_STEAL_NETWORK_ADDRESS = 'steal network address'
    TERM_STEAL_OPEN_PORT = 'steal open port'


class MachineAccessControlTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MachineAccessControlTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'control machine via remote command',
    )
    TERM_CONTROL_MACHINE_VIA_REMOTE_COMMAND = 'control machine via remote command'


class DataTheftProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DataTheftPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'targeted application',
        'targeted website',
    )
    TERM_TARGETED_APPLICATION = 'targeted application'
    TERM_TARGETED_WEBSITE = 'targeted website'


class SecondaryOperationProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SecondaryOperationPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'trigger type',
    )
    TERM_TRIGGER_TYPE = 'trigger type'


class SystemActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SystemActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'add scheduled task',
        'shutdown system',
        'sleep system',
        'get elapsed system up time',
        'get netbios name',
        'set netbios name',
        'get system host name',
        'set system host name',
        'get system time',
        'set system time',
        'get system local time',
        'set system local time',
        'get username',
        'enumerate system handles',
        'get system global flags',
        'set system global flags',
        'get windows directory',
        'get windows system directory',
        'get windows temporary files directory',
    )
    TERM_ENUMERATE_SYSTEM_HANDLES = 'enumerate system handles'
    TERM_ADD_SCHEDULED_TASK = 'add scheduled task'
    TERM_GET_WINDOWS_DIRECTORY = 'get windows directory'
    TERM_SLEEP_SYSTEM = 'sleep system'
    TERM_GET_ELAPSED_SYSTEM_UP_TIME = 'get elapsed system up time'
    TERM_SET_SYSTEM_HOST_NAME = 'set system host name'
    TERM_SHUTDOWN_SYSTEM = 'shutdown system'
    TERM_GET_NETBIOS_NAME = 'get netbios name'
    TERM_GET_SYSTEM_TIME = 'get system time'
    TERM_SET_SYSTEM_LOCAL_TIME = 'set system local time'
    TERM_SET_SYSTEM_TIME = 'set system time'
    TERM_GET_WINDOWS_TEMPORARY_FILES_DIRECTORY = 'get windows temporary files directory'
    TERM_GET_SYSTEM_LOCAL_TIME = 'get system local time'
    TERM_GET_USERNAME = 'get username'
    TERM_SET_NETBIOS_NAME = 'set netbios name'
    TERM_GET_WINDOWS_SYSTEM_DIRECTORY = 'get windows system directory'
    TERM_GET_SYSTEM_HOST_NAME = 'get system host name'
    TERM_GET_SYSTEM_GLOBAL_FLAGS = 'get system global flags'
    TERM_SET_SYSTEM_GLOBAL_FLAGS = 'set system global flags'


class AvailabilityViolationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AvailabilityViolationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'denial of service',
        'compromise local system availability',
        'crack passwords',
        'mine for cryptocurrency',
        'compromise access to information assets',
    )
    TERM_DENIAL_OF_SERVICE = 'denial of service'
    TERM_COMPROMISE_ACCESS_TO_INFORMATION_ASSETS = 'compromise access to information assets'
    TERM_COMPROMISE_LOCAL_SYSTEM_AVAILABILITY = 'compromise local system availability'
    TERM_MINE_FOR_CRYPTOCURRENCY = 'mine for cryptocurrency'
    TERM_CRACK_PASSWORDS = 'crack passwords'


class ActionObjectAssociationType(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'input',
        'output',
        'side-effect',
    )
    TERM_INPUT = 'input'
    TERM_SIDE_EFFECT = 'side-effect'
    TERM_OUTPUT = 'output'


class CommonCapabilityProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:CommonCapabilityPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'encryption algorithm',
        'protocol used',
    )
    TERM_ENCRYPTION_ALGORITHM = 'encryption algorithm'
    TERM_PROTOCOL_USED = 'protocol used'


class RemoteMachineManipulationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:RemoteMachineManipulationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'compromise remote machine',
    )
    TERM_COMPROMISE_REMOTE_MACHINE = 'compromise remote machine'


class PrivilegeEscalationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:PrivilegeEscalationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'impersonate user',
        'escalate user privilege',
    )
    TERM_IMPERSONATE_USER = 'impersonate user'
    TERM_ESCALATE_USER_PRIVILEGE = 'escalate user privilege'


class DebuggingActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DebuggingActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'check for remote debugger',
        'check for kernel debugger',
    )
    TERM_CHECK_FOR_KERNEL_DEBUGGER = 'check for kernel debugger'
    TERM_CHECK_FOR_REMOTE_DEBUGGER = 'check for remote debugger'


class DataExfiltrationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DataExfiltrationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'perform data exfiltration',
        'obfuscate data for exfiltration',
        'stage data for exfiltration',
    )
    TERM_STAGE_DATA_FOR_EXFILTRATION = 'stage data for exfiltration'
    TERM_OBFUSCATE_DATA_FOR_EXFILTRATION = 'obfuscate data for exfiltration'
    TERM_PERFORM_DATA_EXFILTRATION = 'perform data exfiltration'


class DeviceDriverActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DeviceDriverActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'load and call driver',
        'load driver',
        'unload driver',
        'emulate driver',
    )
    TERM_LOAD_AND_CALL_DRIVER = 'load and call driver'
    TERM_UNLOAD_DRIVER = 'unload driver'
    TERM_LOAD_DRIVER = 'load driver'
    TERM_EMULATE_DRIVER = 'emulate driver'


class ImportanceType(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ImportanceTypeVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'high',
        'medium',
        'low',
        'informational',
        'numeric',
        'unknown',
    )
    TERM_MEDIUM = 'medium'
    TERM_UNKNOWN = 'unknown'
    TERM_NUMERIC = 'numeric'
    TERM_HIGH = 'high'
    TERM_LOW = 'low'
    TERM_INFORMATIONAL = 'informational'


class HTTPActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:HTTPActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'send http get request',
        'send http head request',
        'send http post request',
        'send http put request',
        'send http delete request',
        'send http trace request',
        'send http options request',
        'send http connect request',
        'send http patch request',
        'receive http response',
    )
    TERM_SEND_HTTP_PATCH_REQUEST = 'send http patch request'
    TERM_SEND_HTTP_POST_REQUEST = 'send http post request'
    TERM_SEND_HTTP_GET_REQUEST = 'send http get request'
    TERM_SEND_HTTP_HEAD_REQUEST = 'send http head request'
    TERM_RECEIVE_HTTP_RESPONSE = 'receive http response'
    TERM_SEND_HTTP_TRACE_REQUEST = 'send http trace request'
    TERM_SEND_HTTP_OPTIONS_REQUEST = 'send http options request'
    TERM_SEND_HTTP_DELETE_REQUEST = 'send http delete request'
    TERM_SEND_HTTP_CONNECT_REQUEST = 'send http connect request'
    TERM_SEND_HTTP_PUT_REQUEST = 'send http put request'


class AntiDetectionStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiDetectionStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'security software evasion',
        'hide executing code',
        'self-modification',
        'anti-memory forensics',
        'hide non-executing code',
        'hide malware artifacts',
    )
    TERM_SECURITY_SOFTWARE_EVASION = 'security software evasion'
    TERM_HIDE_EXECUTING_CODE = 'hide executing code'
    TERM_SELF_MODIFICATION = 'self-modification'
    TERM_ANTI_MEMORY_FORENSICS = 'anti-memory forensics'
    TERM_HIDE_NON_EXECUTING_CODE = 'hide non-executing code'
    TERM_HIDE_MALWARE_ARTIFACTS = 'hide malware artifacts'


class SocketActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SocketActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'accept socket connection',
        'bind address to socket',
        'create socket',
        'close socket',
        'connect to socket',
        'disconnect from socket',
        'listen on socket',
        'send data on socket',
        'receive data on socket',
        'send data to address on socket',
        'get host by address',
        'get host by name',
    )
    TERM_CLOSE_SOCKET = 'close socket'
    TERM_CONNECT_TO_SOCKET = 'connect to socket'
    TERM_ACCEPT_SOCKET_CONNECTION = 'accept socket connection'
    TERM_SEND_DATA_ON_SOCKET = 'send data on socket'
    TERM_RECEIVE_DATA_ON_SOCKET = 'receive data on socket'
    TERM_SEND_DATA_TO_ADDRESS_ON_SOCKET = 'send data to address on socket'
    TERM_CREATE_SOCKET = 'create socket'
    TERM_DISCONNECT_FROM_SOCKET = 'disconnect from socket'
    TERM_GET_HOST_BY_ADDRESS = 'get host by address'
    TERM_LISTEN_ON_SOCKET = 'listen on socket'
    TERM_BIND_ADDRESS_TO_SOCKET = 'bind address to socket'
    TERM_GET_HOST_BY_NAME = 'get host by name'


class CommandandControlTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:CommandandControlTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'check for payload',
        'validate data',
        'control malware via remote command',
        'send system information',
        'send heartbeat data',
        'generate c2 domain name(s)',
        'update configuration',
    )
    TERM_CHECK_FOR_PAYLOAD = 'check for payload'
    TERM_VALIDATE_DATA = 'validate data'
    TERM_UPDATE_CONFIGURATION = 'update configuration'
    TERM_SEND_SYSTEM_INFORMATION = 'send system information'
    TERM_SEND_HEARTBEAT_DATA = 'send heartbeat data'
    TERM_GENERATE_C2_DOMAIN_NAME_S = 'generate c2 domain name(s)'
    TERM_CONTROL_MALWARE_VIA_REMOTE_COMMAND = 'control malware via remote command'


class HookingActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:HookingActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'add system call hook',
        'add windows hook',
        'hide hook',
    )
    TERM_ADD_SYSTEM_CALL_HOOK = 'add system call hook'
    TERM_HIDE_HOOK = 'hide hook'
    TERM_ADD_WINDOWS_HOOK = 'add windows hook'


class GroupingRelationship(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:GroupingRelationshipVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'same malware family',
        'clustered together',
        'observed together',
        'part of intrusion set',
        'same malware toolkit',
    )
    TERM_PART_OF_INTRUSION_SET = 'part of intrusion set'
    TERM_CLUSTERED_TOGETHER = 'clustered together'
    TERM_SAME_MALWARE_TOOLKIT = 'same malware toolkit'
    TERM_SAME_MALWARE_FAMILY = 'same malware family'
    TERM_OBSERVED_TOGETHER = 'observed together'


class PersistenceProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:PersistencePropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'scope',
    )
    TERM_SCOPE = 'scope'


class DestructionProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DestructionPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'erasure scope',
    )
    TERM_ERASURE_SCOPE = 'erasure scope'


class AntiCodeAnalysisStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiCodeAnalysisStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'anti-debugging',
        'code obfuscation',
        'anti-disassembly',
    )
    TERM_ANTI_DEBUGGING = 'anti-debugging'
    TERM_CODE_OBFUSCATION = 'code obfuscation'
    TERM_ANTI_DISASSEMBLY = 'anti-disassembly'


class AvailabilityViolationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AvailabilityViolationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'compromise data availability',
        'compromise system availability',
        'consume system resources',
    )
    TERM_CONSUME_SYSTEM_RESOURCES = 'consume system resources'
    TERM_COMPROMISE_DATA_AVAILABILITY = 'compromise data availability'
    TERM_COMPROMISE_SYSTEM_AVAILABILITY = 'compromise system availability'


class IPCActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:IPCActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'create named pipe',
        'delete named pipe',
        'connect to named pipe',
        'disconnect from named pipe',
        'read from named pipe',
        'write to named pipe',
        'create mailslot',
        'read from mailslot',
        'write to mailslot',
    )
    TERM_DISCONNECT_FROM_NAMED_PIPE = 'disconnect from named pipe'
    TERM_READ_FROM_NAMED_PIPE = 'read from named pipe'
    TERM_CREATE_MAILSLOT = 'create mailslot'
    TERM_READ_FROM_MAILSLOT = 'read from mailslot'
    TERM_CREATE_NAMED_PIPE = 'create named pipe'
    TERM_DELETE_NAMED_PIPE = 'delete named pipe'
    TERM_WRITE_TO_NAMED_PIPE = 'write to named pipe'
    TERM_CONNECT_TO_NAMED_PIPE = 'connect to named pipe'
    TERM_WRITE_TO_MAILSLOT = 'write to mailslot'


class DirectoryActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DirectoryActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'create directory',
        'delete directory',
        'monitor directory',
        'hide directory',
    )
    TERM_MONITOR_DIRECTORY = 'monitor directory'
    TERM_DELETE_DIRECTORY = 'delete directory'
    TERM_CREATE_DIRECTORY = 'create directory'
    TERM_HIDE_DIRECTORY = 'hide directory'


class NetworkShareActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:NetworkShareActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'add connection to network share',
        'add network share',
        'delete network share',
        'connect to network share',
        'disconnect from network share',
        'enumerate network shares',
    )
    TERM_ENUMERATE_NETWORK_SHARES = 'enumerate network shares'
    TERM_DISCONNECT_FROM_NETWORK_SHARE = 'disconnect from network share'
    TERM_ADD_NETWORK_SHARE = 'add network share'
    TERM_ADD_CONNECTION_TO_NETWORK_SHARE = 'add connection to network share'
    TERM_DELETE_NETWORK_SHARE = 'delete network share'
    TERM_CONNECT_TO_NETWORK_SHARE = 'connect to network share'


class InfectionPropagationProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:InfectionPropagationPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'scope',
        'infection targeting',
        'autonomy',
        'targeted file type',
        'targeted file architecture type',
        'file infection type',
    )
    TERM_AUTONOMY = 'autonomy'
    TERM_TARGETED_FILE_TYPE = 'targeted file type'
    TERM_FILE_INFECTION_TYPE = 'file infection type'
    TERM_INFECTION_TARGETING = 'infection targeting'
    TERM_SCOPE = 'scope'
    TERM_TARGETED_FILE_ARCHITECTURE_TYPE = 'targeted file architecture type'


class ProbingStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ProbingStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'probe host configuration',
        'probe network environment',
    )
    TERM_PROBE_NETWORK_ENVIRONMENT = 'probe network environment'
    TERM_PROBE_HOST_CONFIGURATION = 'probe host configuration'


class InfectionPropagationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:InfectionPropagationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'identify file',
        'perform autonomous remote infection',
        'identify target machine(s)',
        'perform social-engineering based remote infection',
        'inventory victims',
        'write code into file',
        'modify file',
    )
    TERM_IDENTIFY_FILE = 'identify file'
    TERM_PERFORM_AUTONOMOUS_REMOTE_INFECTION = 'perform autonomous remote infection'
    TERM_IDENTIFY_TARGET_MACHINE_S = 'identify target machine(s)'
    TERM_PERFORM_SOCIAL_ENGINEERING_BASED_REMOTE_INFECTION = 'perform social-engineering based remote infection'
    TERM_INVENTORY_VICTIMS = 'inventory victims'
    TERM_WRITE_CODE_INTO_FILE = 'write code into file'
    TERM_MODIFY_FILE = 'modify file'


class DataExfiltrationProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DataExfiltrationPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'archive type',
        'file type',
    )
    TERM_ARCHIVE_TYPE = 'archive type'
    TERM_FILE_TYPE = 'file type'


class LibraryActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:LibraryActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'enumerate libraries',
        'free library',
        'load library',
        'get function address',
        'call library function',
    )
    TERM_GET_FUNCTION_ADDRESS = 'get function address'
    TERM_LOAD_LIBRARY = 'load library'
    TERM_CALL_LIBRARY_FUNCTION = 'call library function'
    TERM_FREE_LIBRARY = 'free library'
    TERM_ENUMERATE_LIBRARIES = 'enumerate libraries'


class MalwareDevelopmentTool(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MalwareDevelopmentToolVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'builder',
        'compiler',
        'linker',
        'packer',
        'crypter',
        'protector',
    )
    TERM_PACKER = 'packer'
    TERM_BUILDER = 'builder'
    TERM_LINKER = 'linker'
    TERM_CRYPTER = 'crypter'
    TERM_PROTECTOR = 'protector'
    TERM_COMPILER = 'compiler'


class FileActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:FileActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'create file',
        'delete file',
        'copy file',
        'create file symbolic link',
        'find file',
        'get file attributes',
        'set file attributes',
        'lock file',
        'unlock file',
        'modify file',
        'move file',
        'open file',
        'read from file',
        'write to file',
        'rename file',
        'create file alternate data stream',
        'send control code to file',
        'create file mapping',
        'open file mapping',
        'execute file',
        'hide file',
        'close file',
    )
    TERM_CREATE_FILE_MAPPING = 'create file mapping'
    TERM_FIND_FILE = 'find file'
    TERM_READ_FROM_FILE = 'read from file'
    TERM_MOVE_FILE = 'move file'
    TERM_CREATE_FILE_SYMBOLIC_LINK = 'create file symbolic link'
    TERM_SEND_CONTROL_CODE_TO_FILE = 'send control code to file'
    TERM_WRITE_TO_FILE = 'write to file'
    TERM_EXECUTE_FILE = 'execute file'
    TERM_CLOSE_FILE = 'close file'
    TERM_COPY_FILE = 'copy file'
    TERM_CREATE_FILE_ALTERNATE_DATA_STREAM = 'create file alternate data stream'
    TERM_LOCK_FILE = 'lock file'
    TERM_HIDE_FILE = 'hide file'
    TERM_UNLOCK_FILE = 'unlock file'
    TERM_GET_FILE_ATTRIBUTES = 'get file attributes'
    TERM_RENAME_FILE = 'rename file'
    TERM_OPEN_FILE_MAPPING = 'open file mapping'
    TERM_DELETE_FILE = 'delete file'
    TERM_SET_FILE_ATTRIBUTES = 'set file attributes'
    TERM_OPEN_FILE = 'open file'
    TERM_CREATE_FILE = 'create file'
    TERM_MODIFY_FILE = 'modify file'


class CommandandControlProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:CommandandControlPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'frequency',
    )
    TERM_FREQUENCY = 'frequency'


class IRCActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:IRCActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'connect to irc server',
        'disconnect from irc server',
        'set irc nickname',
        'join irc channel',
        'leave irc channel',
        'send irc private message',
        'receive irc private message',
    )
    TERM_RECEIVE_IRC_PRIVATE_MESSAGE = 'receive irc private message'
    TERM_JOIN_IRC_CHANNEL = 'join irc channel'
    TERM_SEND_IRC_PRIVATE_MESSAGE = 'send irc private message'
    TERM_LEAVE_IRC_CHANNEL = 'leave irc channel'
    TERM_CONNECT_TO_IRC_SERVER = 'connect to irc server'
    TERM_DISCONNECT_FROM_IRC_SERVER = 'disconnect from irc server'
    TERM_SET_IRC_NICKNAME = 'set irc nickname'


class InfectionPropagationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:InfectionPropagationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'prevent duplicate infection',
        'infect file',
        'infect remote machine',
    )
    TERM_INFECT_FILE = 'infect file'
    TERM_PREVENT_DUPLICATE_INFECTION = 'prevent duplicate infection'
    TERM_INFECT_REMOTE_MACHINE = 'infect remote machine'


class MalwareCapability(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MalwareCapabilityVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'command and control',
        'remote machine manipulation',
        'privilege escalation',
        'data theft',
        'spying',
        'secondary operation',
        'anti-detection',
        'anti-code analysis',
        'infection/propagation',
        'anti-behavioral analysis',
        'integrity violation',
        'data exfiltration',
        'probing',
        'anti-removal',
        'security degradation',
        'availability violation',
        'destruction',
        'fraud',
        'persistence',
        'machine access/control',
    )
    TERM_COMMAND_AND_CONTROL = 'command and control'
    TERM_REMOTE_MACHINE_MANIPULATION = 'remote machine manipulation'
    TERM_INFECTION_PROPAGATION = 'infection/propagation'
    TERM_SPYING = 'spying'
    TERM_SECONDARY_OPERATION = 'secondary operation'
    TERM_ANTI_DETECTION = 'anti-detection'
    TERM_ANTI_BEHAVIORAL_ANALYSIS = 'anti-behavioral analysis'
    TERM_MACHINE_ACCESS_CONTROL = 'machine access/control'
    TERM_DATA_THEFT = 'data theft'
    TERM_ANTI_CODE_ANALYSIS = 'anti-code analysis'
    TERM_INTEGRITY_VIOLATION = 'integrity violation'
    TERM_DATA_EXFILTRATION = 'data exfiltration'
    TERM_SECURITY_DEGRADATION = 'security degradation'
    TERM_ANTI_REMOVAL = 'anti-removal'
    TERM_PRIVILEGE_ESCALATION = 'privilege escalation'
    TERM_AVAILABILITY_VIOLATION = 'availability violation'
    TERM_FRAUD = 'fraud'
    TERM_PROBING = 'probing'
    TERM_PERSISTENCE = 'persistence'
    TERM_DESTRUCTION = 'destruction'


class AntiBehavioralAnalysisProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiBehavioralAnalysisPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'targeted vm',
        'targeted sandbox',
    )
    TERM_TARGETED_VM = 'targeted vm'
    TERM_TARGETED_SANDBOX = 'targeted sandbox'


class DNSActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DNSActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'send dns query',
        'send reverse dns lookup',
    )
    TERM_SEND_DNS_QUERY = 'send dns query'
    TERM_SEND_REVERSE_DNS_LOOKUP = 'send reverse dns lookup'


class RemoteMachineManipulationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:RemoteMachineManipulationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'access remote machine',
        'search for remote machines',
    )
    TERM_ACCESS_REMOTE_MACHINE = 'access remote machine'
    TERM_SEARCH_FOR_REMOTE_MACHINES = 'search for remote machines'


class ProcessActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ProcessActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'create process',
        'kill process',
        'create process as user',
        'enumerate processes',
        'open process',
        'flush process instruction cache',
        'get process current directory',
        'set process current directory',
        'get process environment variable',
        'set process environment variable',
        'sleep process',
        'get process startupinfo',
    )
    TERM_GET_PROCESS_CURRENT_DIRECTORY = 'get process current directory'
    TERM_SET_PROCESS_ENVIRONMENT_VARIABLE = 'set process environment variable'
    TERM_ENUMERATE_PROCESSES = 'enumerate processes'
    TERM_SET_PROCESS_CURRENT_DIRECTORY = 'set process current directory'
    TERM_GET_PROCESS_ENVIRONMENT_VARIABLE = 'get process environment variable'
    TERM_SLEEP_PROCESS = 'sleep process'
    TERM_FLUSH_PROCESS_INSTRUCTION_CACHE = 'flush process instruction cache'
    TERM_KILL_PROCESS = 'kill process'
    TERM_CREATE_PROCESS = 'create process'
    TERM_GET_PROCESS_STARTUPINFO = 'get process startupinfo'
    TERM_CREATE_PROCESS_AS_USER = 'create process as user'
    TERM_OPEN_PROCESS = 'open process'


class PersistenceStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:PersistenceStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'persist to re-infect system',
        'gather information for improvement',
        'ensure compatibility',
        'persist to continuously execute on system',
    )
    TERM_PERSIST_TO_RE_INFECT_SYSTEM = 'persist to re-infect system'
    TERM_GATHER_INFORMATION_FOR_IMPROVEMENT = 'gather information for improvement'
    TERM_ENSURE_COMPATIBILITY = 'ensure compatibility'
    TERM_PERSIST_TO_CONTINUOUSLY_EXECUTE_ON_SYSTEM = 'persist to continuously execute on system'


class NetworkActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:NetworkActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'open port',
        'close port',
        'connect to ip',
        'disconnect from ip',
        'connect to url',
        'connect to socket address',
        'download file',
        'upload file',
        'listen on port',
        'send email message',
        'send icmp request',
        'send network packet',
        'receive network packet',
    )
    TERM_SEND_EMAIL_MESSAGE = 'send email message'
    TERM_SEND_NETWORK_PACKET = 'send network packet'
    TERM_DISCONNECT_FROM_IP = 'disconnect from ip'
    TERM_CONNECT_TO_IP = 'connect to ip'
    TERM_CLOSE_PORT = 'close port'
    TERM_DOWNLOAD_FILE = 'download file'
    TERM_SEND_ICMP_REQUEST = 'send icmp request'
    TERM_CONNECT_TO_URL = 'connect to url'
    TERM_CONNECT_TO_SOCKET_ADDRESS = 'connect to socket address'
    TERM_OPEN_PORT = 'open port'
    TERM_UPLOAD_FILE = 'upload file'
    TERM_LISTEN_ON_PORT = 'listen on port'
    TERM_RECEIVE_NETWORK_PACKET = 'receive network packet'


class SecondaryOperationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SecondaryOperationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'patch operating system file(s)',
        'remove traces of infection',
        'log activity',
        'lay dormant',
        'install other components',
        'suicide exit',
    )
    TERM_PATCH_OPERATING_SYSTEM_FILE_S = 'patch operating system file(s)'
    TERM_REMOVE_TRACES_OF_INFECTION = 'remove traces of infection'
    TERM_LAY_DORMANT = 'lay dormant'
    TERM_INSTALL_OTHER_COMPONENTS = 'install other components'
    TERM_SUICIDE_EXIT = 'suicide exit'
    TERM_LOG_ACTIVITY = 'log activity'


class FraudTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:FraudTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'access premium service',
    )
    TERM_ACCESS_PREMIUM_SERVICE = 'access premium service'


class ProcessMemoryActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ProcessMemoryActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'allocate process virtual memory',
        'free process virtual memory',
        'modify process virtual memory protection',
        'read from process memory',
        'write to process memory',
        'map file into process',
        'unmap file from process',
        'map library into process',
    )
    TERM_UNMAP_FILE_FROM_PROCESS = 'unmap file from process'
    TERM_MODIFY_PROCESS_VIRTUAL_MEMORY_PROTECTION = 'modify process virtual memory protection'
    TERM_WRITE_TO_PROCESS_MEMORY = 'write to process memory'
    TERM_READ_FROM_PROCESS_MEMORY = 'read from process memory'
    TERM_ALLOCATE_PROCESS_VIRTUAL_MEMORY = 'allocate process virtual memory'
    TERM_MAP_LIBRARY_INTO_PROCESS = 'map library into process'
    TERM_FREE_PROCESS_VIRTUAL_MEMORY = 'free process virtual memory'
    TERM_MAP_FILE_INTO_PROCESS = 'map file into process'


class RegistryActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:RegistryActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'create registry key',
        'delete registry key',
        'open registry key',
        'close registry key',
        'create registry key value',
        'delete registry key value',
        'enumerate registry key subkeys',
        'enumerate registry key values',
        'get registry key attributes',
        'read registry key value',
        'modify registry key value',
        'modify registry key',
        'monitor registry key',
    )
    TERM_MODIFY_REGISTRY_KEY = 'modify registry key'
    TERM_MONITOR_REGISTRY_KEY = 'monitor registry key'
    TERM_CLOSE_REGISTRY_KEY = 'close registry key'
    TERM_DELETE_REGISTRY_KEY = 'delete registry key'
    TERM_OPEN_REGISTRY_KEY = 'open registry key'
    TERM_ENUMERATE_REGISTRY_KEY_SUBKEYS = 'enumerate registry key subkeys'
    TERM_ENUMERATE_REGISTRY_KEY_VALUES = 'enumerate registry key values'
    TERM_READ_REGISTRY_KEY_VALUE = 'read registry key value'
    TERM_GET_REGISTRY_KEY_ATTRIBUTES = 'get registry key attributes'
    TERM_CREATE_REGISTRY_KEY_VALUE = 'create registry key value'
    TERM_CREATE_REGISTRY_KEY = 'create registry key'
    TERM_MODIFY_REGISTRY_KEY_VALUE = 'modify registry key value'
    TERM_DELETE_REGISTRY_KEY_VALUE = 'delete registry key value'


class AvailabilityViolationProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AvailabilityViolationPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'cryptocurrency type',
    )
    TERM_CRYPTOCURRENCY_TYPE = 'cryptocurrency type'


class CommandandControlStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:CommandandControlStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'determine c2 server',
        'receive data from c2 server',
        'send data to c2 server',
    )
    TERM_DETERMINE_C2_SERVER = 'determine c2 server'
    TERM_RECEIVE_DATA_FROM_C2_SERVER = 'receive data from c2 server'
    TERM_SEND_DATA_TO_C2_SERVER = 'send data to c2 server'


class DestructionTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DestructionTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'erase data',
        'destroy firmware',
        'destroy hardware',
    )
    TERM_ERASE_DATA = 'erase data'
    TERM_DESTROY_FIRMWARE = 'destroy firmware'
    TERM_DESTROY_HARDWARE = 'destroy hardware'


class SpyingStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SpyingStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'capture system input peripheral data',
        'capture system state data',
        'capture system interface data',
        'capture system output peripheral data',
    )
    TERM_CAPTURE_SYSTEM_INPUT_PERIPHERAL_DATA = 'capture system input peripheral data'
    TERM_CAPTURE_SYSTEM_INTERFACE_DATA = 'capture system interface data'
    TERM_CAPTURE_SYSTEM_OUTPUT_PERIPHERAL_DATA = 'capture system output peripheral data'
    TERM_CAPTURE_SYSTEM_STATE_DATA = 'capture system state data'


class FTPActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:FTPActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'connect to ftp server',
        'disconnect from ftp server',
        'send ftp command',
    )
    TERM_CONNECT_TO_FTP_SERVER = 'connect to ftp server'
    TERM_SEND_FTP_COMMAND = 'send ftp command'
    TERM_DISCONNECT_FROM_FTP_SERVER = 'disconnect from ftp server'


class MachineAccessControlStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MachineAccessControlStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'control local machine',
        'install backdoor',
    )
    TERM_CONTROL_LOCAL_MACHINE = 'control local machine'
    TERM_INSTALL_BACKDOOR = 'install backdoor'


class IntegrityViolationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:IntegrityViolationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'compromise system operational integrity',
        'compromise user data integrity',
        'annoy user',
        'compromise network operational integrity',
        'compromise system data integrity',
    )
    TERM_COMPROMISE_SYSTEM_DATA_INTEGRITY = 'compromise system data integrity'
    TERM_ANNOY_USER = 'annoy user'
    TERM_COMPROMISE_NETWORK_OPERATIONAL_INTEGRITY = 'compromise network operational integrity'
    TERM_COMPROMISE_USER_DATA_INTEGRITY = 'compromise user data integrity'
    TERM_COMPROMISE_SYSTEM_OPERATIONAL_INTEGRITY = 'compromise system operational integrity'


class ProbingTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ProbingTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'identify os',
        'check for proxy',
        'check for firewall',
        'check for network drives',
        'map local network',
        'inventory system applications',
        'check language',
        'check for internet connectivity',
    )
    TERM_IDENTIFY_OS = 'identify os'
    TERM_CHECK_FOR_PROXY = 'check for proxy'
    TERM_INVENTORY_SYSTEM_APPLICATIONS = 'inventory system applications'
    TERM_CHECK_FOR_NETWORK_DRIVES = 'check for network drives'
    TERM_MAP_LOCAL_NETWORK = 'map local network'
    TERM_CHECK_FOR_FIREWALL = 'check for firewall'
    TERM_CHECK_LANGUAGE = 'check language'
    TERM_CHECK_FOR_INTERNET_CONNECTIVITY = 'check for internet connectivity'


class MalwareEntityType(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MalwareEntityTypeVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'instance',
        'family',
        'class',
    )
    TERM_INSTANCE = 'instance'
    TERM_CLASS = 'class'
    TERM_FAMILY = 'family'


class FraudStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:FraudStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'perform premium rate fraud',
        'perform click fraud',
    )
    TERM_PERFORM_CLICK_FRAUD = 'perform click fraud'
    TERM_PERFORM_PREMIUM_RATE_FRAUD = 'perform premium rate fraud'


class SpyingTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SpyingTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'capture system screenshot',
        'capture camera input',
        'capture file system',
        'capture printer output',
        'capture gps data',
        'capture keyboard input',
        'capture mouse input',
        'capture microphone input',
        'capture system network traffic',
        'capture touchscreen input',
        'capture system memory',
    )
    TERM_CAPTURE_SYSTEM_SCREENSHOT = 'capture system screenshot'
    TERM_CAPTURE_KEYBOARD_INPUT = 'capture keyboard input'
    TERM_CAPTURE_FILE_SYSTEM = 'capture file system'
    TERM_CAPTURE_CAMERA_INPUT = 'capture camera input'
    TERM_CAPTURE_GPS_DATA = 'capture gps data'
    TERM_CAPTURE_PRINTER_OUTPUT = 'capture printer output'
    TERM_CAPTURE_MOUSE_INPUT = 'capture mouse input'
    TERM_CAPTURE_MICROPHONE_INPUT = 'capture microphone input'
    TERM_CAPTURE_SYSTEM_NETWORK_TRAFFIC = 'capture system network traffic'
    TERM_CAPTURE_TOUCHSCREEN_INPUT = 'capture touchscreen input'
    TERM_CAPTURE_SYSTEM_MEMORY = 'capture system memory'


class ProcessThreadActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ProcessThreadActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'create thread',
        'kill thread',
        'create remote thread in process',
        'enumerate threads',
        'get thread username',
        'impersonate process',
        'revert thread to self',
        'get thread context',
        'set thread context',
        'queue apc in thread',
    )
    TERM_CREATE_THREAD = 'create thread'
    TERM_SET_THREAD_CONTEXT = 'set thread context'
    TERM_ENUMERATE_THREADS = 'enumerate threads'
    TERM_QUEUE_APC_IN_THREAD = 'queue apc in thread'
    TERM_GET_THREAD_USERNAME = 'get thread username'
    TERM_REVERT_THREAD_TO_SELF = 'revert thread to self'
    TERM_CREATE_REMOTE_THREAD_IN_PROCESS = 'create remote thread in process'
    TERM_GET_THREAD_CONTEXT = 'get thread context'
    TERM_KILL_THREAD = 'kill thread'
    TERM_IMPERSONATE_PROCESS = 'impersonate process'


class DataTheftStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DataTheftStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'steal stored information',
        'steal user data',
        'steal system information',
        'steal authentication credentials',
    )
    TERM_STEAL_STORED_INFORMATION = 'steal stored information'
    TERM_STEAL_USER_DATA = 'steal user data'
    TERM_STEAL_SYSTEM_INFORMATION = 'steal system information'
    TERM_STEAL_AUTHENTICATION_CREDENTIALS = 'steal authentication credentials'


class AntiCodeAnalysisTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiCodeAnalysisTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'transform control flow',
        'restructure arrays',
        'detect debugging',
        'prevent debugging',
        'defeat flow-oriented (recursive traversal) disassembler',
        'defeat linear disassembler',
        'obfuscate instructions',
        'obfuscate imports',
        'defeat call graph generation',
        'obfuscate runtime code',
    )
    TERM_DEFEAT_CALL_GRAPH_GENERATION = 'defeat call graph generation'
    TERM_RESTRUCTURE_ARRAYS = 'restructure arrays'
    TERM_DETECT_DEBUGGING = 'detect debugging'
    TERM_PREVENT_DEBUGGING = 'prevent debugging'
    TERM_DEFEAT_FLOW_ORIENTED_RECURSIVE_TRAVERSAL_DISASSEMBLER = 'defeat flow-oriented (recursive traversal) disassembler'
    TERM_DEFEAT_LINEAR_DISASSEMBLER = 'defeat linear disassembler'
    TERM_OBFUSCATE_INSTRUCTIONS = 'obfuscate instructions'
    TERM_OBFUSCATE_IMPORTS = 'obfuscate imports'
    TERM_TRANSFORM_CONTROL_FLOW = 'transform control flow'
    TERM_OBFUSCATE_RUNTIME_CODE = 'obfuscate runtime code'


class PrivilegeEscalationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:PrivilegeEscalationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'elevate cpu mode',
    )
    TERM_ELEVATE_CPU_MODE = 'elevate cpu mode'


class MalwareSubjectRelationship(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MalwareSubjectRelationshipVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'downloads',
        'downloaded by',
        'drops',
        'dropped by',
        'extracts',
        'extracted from',
        'direct descendant of',
        'direct ancestor of',
        'memory image of',
        'contained in memory image',
        'disk image of',
        'contained in disk image',
        'network traffic capture of',
        'contained in network traffic capture',
        'packed version of',
        'unpacked version of',
        'installs',
        'installed by',
        '64-bit version of',
        '32-bit version of',
        'encrypted version of',
        'decrypted version of',
    )
    TERM_NETWORK_TRAFFIC_CAPTURE_OF = 'network traffic capture of'
    TERM_64_BIT_VERSION_OF = '64-bit version of'
    TERM_DROPPED_BY = 'dropped by'
    TERM_MEMORY_IMAGE_OF = 'memory image of'
    TERM_32_BIT_VERSION_OF = '32-bit version of'
    TERM_INSTALLED_BY = 'installed by'
    TERM_DIRECT_DESCENDANT_OF = 'direct descendant of'
    TERM_DIRECT_ANCESTOR_OF = 'direct ancestor of'
    TERM_DROPS = 'drops'
    TERM_DOWNLOADS = 'downloads'
    TERM_ENCRYPTED_VERSION_OF = 'encrypted version of'
    TERM_EXTRACTED_FROM = 'extracted from'
    TERM_DISK_IMAGE_OF = 'disk image of'
    TERM_PACKED_VERSION_OF = 'packed version of'
    TERM_CONTAINED_IN_MEMORY_IMAGE = 'contained in memory image'
    TERM_UNPACKED_VERSION_OF = 'unpacked version of'
    TERM_CONTAINED_IN_NETWORK_TRAFFIC_CAPTURE = 'contained in network traffic capture'
    TERM_INSTALLS = 'installs'
    TERM_EXTRACTS = 'extracts'
    TERM_DOWNLOADED_BY = 'downloaded by'
    TERM_CONTAINED_IN_DISK_IMAGE = 'contained in disk image'
    TERM_DECRYPTED_VERSION_OF = 'decrypted version of'


class AntiBehavioralAnalysisTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiBehavioralAnalysisTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'detect vm environment',
        'overload sandbox',
        'prevent execution in sandbox',
        'detect sandbox environment',
        'prevent execution in vm',
    )
    TERM_DETECT_VM_ENVIRONMENT = 'detect vm environment'
    TERM_OVERLOAD_SANDBOX = 'overload sandbox'
    TERM_PREVENT_EXECUTION_IN_SANDBOX = 'prevent execution in sandbox'
    TERM_DETECT_SANDBOX_ENVIRONMENT = 'detect sandbox environment'
    TERM_PREVENT_EXECUTION_IN_VM = 'prevent execution in vm'


class PersistenceTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:PersistenceTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'reinstantiate self after initial detection',
        'limit application type/version',
        'persist after os install/reinstall',
        'drop/retrieve debug log file',
        'persist independent of hard disk/os changes',
        'persist after system reboot',
    )
    TERM_REINSTANTIATE_SELF_AFTER_INITIAL_DETECTION = 'reinstantiate self after initial detection'
    TERM_LIMIT_APPLICATION_TYPE_VERSION = 'limit application type/version'
    TERM_PERSIST_AFTER_OS_INSTALL_REINSTALL = 'persist after os install/reinstall'
    TERM_DROP_RETRIEVE_DEBUG_LOG_FILE = 'drop/retrieve debug log file'
    TERM_PERSIST_INDEPENDENT_OF_HARD_DISK_OS_CHANGES = 'persist independent of hard disk/os changes'
    TERM_PERSIST_AFTER_SYSTEM_REBOOT = 'persist after system reboot'


class SynchronizationActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SynchronizationActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'create mutex',
        'delete mutex',
        'open mutex',
        'release mutex',
        'create semaphore',
        'delete semaphore',
        'open semaphore',
        'release semaphore',
        'create event',
        'delete event',
        'open event',
        'reset event',
        'create critical section',
        'delete critical section',
        'open critical section',
        'release critical section',
    )
    TERM_CREATE_EVENT = 'create event'
    TERM_CREATE_MUTEX = 'create mutex'
    TERM_OPEN_MUTEX = 'open mutex'
    TERM_DELETE_MUTEX = 'delete mutex'
    TERM_OPEN_SEMAPHORE = 'open semaphore'
    TERM_OPEN_EVENT = 'open event'
    TERM_RELEASE_MUTEX = 'release mutex'
    TERM_DELETE_CRITICAL_SECTION = 'delete critical section'
    TERM_CREATE_CRITICAL_SECTION = 'create critical section'
    TERM_RELEASE_SEMAPHORE = 'release semaphore'
    TERM_DELETE_EVENT = 'delete event'
    TERM_RESET_EVENT = 'reset event'
    TERM_RELEASE_CRITICAL_SECTION = 'release critical section'
    TERM_CREATE_SEMAPHORE = 'create semaphore'
    TERM_DELETE_SEMAPHORE = 'delete semaphore'
    TERM_OPEN_CRITICAL_SECTION = 'open critical section'


class AntiRemovalTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiRemovalTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'prevent registry deletion',
        'prevent api unhooking',
        'prevent file access',
        'prevent memory access',
        'prevent registry access',
        'prevent file deletion',
    )
    TERM_PREVENT_REGISTRY_DELETION = 'prevent registry deletion'
    TERM_PREVENT_API_UNHOOKING = 'prevent api unhooking'
    TERM_PREVENT_FILE_ACCESS = 'prevent file access'
    TERM_PREVENT_MEMORY_ACCESS = 'prevent memory access'
    TERM_PREVENT_REGISTRY_ACCESS = 'prevent registry access'
    TERM_PREVENT_FILE_DELETION = 'prevent file deletion'


class SecurityDegradationStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SecurityDegradationStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'disable service provider security features',
        'degrade security programs',
        'disable system updates',
        'disable os security features',
        'disable [host-based or os] access controls',
    )
    TERM_DISABLE_SERVICE_PROVIDER_SECURITY_FEATURES = 'disable service provider security features'
    TERM_DEGRADE_SECURITY_PROGRAMS = 'degrade security programs'
    TERM_DISABLE_SYSTEM_UPDATES = 'disable system updates'
    TERM_DISABLE_OS_SECURITY_FEATURES = 'disable os security features'
    TERM_DISABLE_HOST_BASED_OR_OS_ACCESS_CONTROLS = 'disable [host-based or os] access controls'


class PrivilegeEscalationProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:PrivilegeEscalationPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'user privilege escalation type',
    )
    TERM_USER_PRIVILEGE_ESCALATION_TYPE = 'user privilege escalation type'


class GUIActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:GUIActionNameVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'create window',
        'kill window',
        'create dialog box',
        'enumerate windows',
        'find window',
        'hide window',
        'show window',
    )
    TERM_FIND_WINDOW = 'find window'
    TERM_SHOW_WINDOW = 'show window'
    TERM_KILL_WINDOW = 'kill window'
    TERM_ENUMERATE_WINDOWS = 'enumerate windows'
    TERM_CREATE_WINDOW = 'create window'
    TERM_CREATE_DIALOG_BOX = 'create dialog box'
    TERM_HIDE_WINDOW = 'hide window'


class SecurityDegradationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SecurityDegradationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'stop execution of security program',
        'disable firewall',
        'disable access right checking',
        'disable kernel patching protection',
        'prevent access to security websites',
        'remove sms warning messages',
        'modify security program configuration',
        'prevent security program from running',
        'disable system update services/daemons',
        'disable system service pack/patch installation',
        'disable system file overwrite protection',
        'disable privilege limiting',
        'gather security product info',
        'disable os security alerts',
        'disable user account control',
    )
    TERM_STOP_EXECUTION_OF_SECURITY_PROGRAM = 'stop execution of security program'
    TERM_DISABLE_FIREWALL = 'disable firewall'
    TERM_DISABLE_ACCESS_RIGHT_CHECKING = 'disable access right checking'
    TERM_DISABLE_KERNEL_PATCHING_PROTECTION = 'disable kernel patching protection'
    TERM_PREVENT_SECURITY_PROGRAM_FROM_RUNNING = 'prevent security program from running'
    TERM_REMOVE_SMS_WARNING_MESSAGES = 'remove sms warning messages'
    TERM_MODIFY_SECURITY_PROGRAM_CONFIGURATION = 'modify security program configuration'
    TERM_PREVENT_ACCESS_TO_SECURITY_WEBSITES = 'prevent access to security websites'
    TERM_DISABLE_SYSTEM_UPDATE_SERVICES_DAEMONS = 'disable system update services/daemons'
    TERM_DISABLE_SYSTEM_SERVICE_PACK_PATCH_INSTALLATION = 'disable system service pack/patch installation'
    TERM_DISABLE_SYSTEM_FILE_OVERWRITE_PROTECTION = 'disable system file overwrite protection'
    TERM_DISABLE_PRIVILEGE_LIMITING = 'disable privilege limiting'
    TERM_GATHER_SECURITY_PRODUCT_INFO = 'gather security product info'
    TERM_DISABLE_OS_SECURITY_ALERTS = 'disable os security alerts'
    TERM_DISABLE_USER_ACCOUNT_CONTROL = 'disable user account control'


class MalwareConfigurationParameter(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MalwareConfigurationParameterVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'magic number',
        'id',
        'group id',
        'mutex',
        'filename',
        'installation path',
    )
    TERM_MAGIC_NUMBER = 'magic number'
    TERM_GROUP_ID = 'group id'
    TERM_FILENAME = 'filename'
    TERM_MUTEX = 'mutex'
    TERM_INSTALLATION_PATH = 'installation path'
    TERM_ID = 'id'


class MachineAccessControlProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MachineAccessControlPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'backdoor type',
    )
    TERM_BACKDOOR_TYPE = 'backdoor type'


class ServiceActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:ServiceActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'create service',
        'delete service',
        'start service',
        'stop service',
        'enumerate services',
        'modify service configuration',
        'open service',
        'send control code to service',
    )
    TERM_SEND_CONTROL_CODE_TO_SERVICE = 'send control code to service'
    TERM_MODIFY_SERVICE_CONFIGURATION = 'modify service configuration'
    TERM_CREATE_SERVICE = 'create service'
    TERM_START_SERVICE = 'start service'
    TERM_ENUMERATE_SERVICES = 'enumerate services'
    TERM_STOP_SERVICE = 'stop service'
    TERM_DELETE_SERVICE = 'delete service'
    TERM_OPEN_SERVICE = 'open service'


class AntiBehavioralAnalysisStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiBehavioralAnalysisStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'anti-vm',
        'anti-sandbox',
    )
    TERM_ANTI_VM = 'anti-vm'
    TERM_ANTI_SANDBOX = 'anti-sandbox'


class CapabilityObjectiveRelationship(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:CapabilityObjectiveRelationshipVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'child of',
        'parent of',
        'incorporates',
        'incorporated by',
    )
    TERM_CHILD_OF = 'child of'
    TERM_PARENT_OF = 'parent of'
    TERM_INCORPORATED_BY = 'incorporated by'
    TERM_INCORPORATES = 'incorporates'


class DataExfiltrationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DataExfiltrationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'exfiltrate via covert channel',
        'exfiltrate via fax',
        'exfiltrate via physical media',
        'encrypt data',
        'exfiltrate via network',
        'hide data',
        'package data',
        'exfiltrate via dumpster dive',
        'move data to staging server',
        'exfiltrate via voip/phone',
    )
    TERM_EXFILTRATE_VIA_COVERT_CHANNEL = 'exfiltrate via covert channel'
    TERM_EXFILTRATE_VIA_FAX = 'exfiltrate via fax'
    TERM_EXFILTRATE_VIA_PHYSICAL_MEDIA = 'exfiltrate via physical media'
    TERM_ENCRYPT_DATA = 'encrypt data'
    TERM_EXFILTRATE_VIA_NETWORK = 'exfiltrate via network'
    TERM_HIDE_DATA = 'hide data'
    TERM_PACKAGE_DATA = 'package data'
    TERM_EXFILTRATE_VIA_DUMPSTER_DIVE = 'exfiltrate via dumpster dive'
    TERM_MOVE_DATA_TO_STAGING_SERVER = 'move data to staging server'
    TERM_EXFILTRATE_VIA_VOIP_PHONE = 'exfiltrate via voip/phone'


class UserActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:UserActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'add user',
        'delete user',
        'enumerate users',
        'get user attributes',
        'logon as user',
        'change password',
        'add user to group',
        'remove user from group',
        'invoke user privilege',
    )
    TERM_DELETE_USER = 'delete user'
    TERM_CHANGE_PASSWORD = 'change password'
    TERM_LOGON_AS_USER = 'logon as user'
    TERM_ENUMERATE_USERS = 'enumerate users'
    TERM_REMOVE_USER_FROM_GROUP = 'remove user from group'
    TERM_ADD_USER_TO_GROUP = 'add user to group'
    TERM_ADD_USER = 'add user'
    TERM_INVOKE_USER_PRIVILEGE = 'invoke user privilege'
    TERM_GET_USER_ATTRIBUTES = 'get user attributes'


class DestructionStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DestructionStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'destroy physical entity',
        'destroy virtual entity',
    )
    TERM_DESTROY_PHYSICAL_ENTITY = 'destroy physical entity'
    TERM_DESTROY_VIRTUAL_ENTITY = 'destroy virtual entity'


class AntiRemovalStrategicObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiRemovalStrategicObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'prevent malware artifact access',
        'prevent malware artifact deletion',
    )
    TERM_PREVENT_MALWARE_ARTIFACT_ACCESS = 'prevent malware artifact access'
    TERM_PREVENT_MALWARE_ARTIFACT_DELETION = 'prevent malware artifact deletion'


class SecondaryOperationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SecondaryOperationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'install secondary module',
        'install secondary malware',
        'install legitimate software',
        'remove self',
        'remove system artifacts',
    )
    TERM_INSTALL_SECONDARY_MODULE = 'install secondary module'
    TERM_INSTALL_SECONDARY_MALWARE = 'install secondary malware'
    TERM_INSTALL_LEGITIMATE_SOFTWARE = 'install legitimate software'
    TERM_REMOVE_SELF = 'remove self'
    TERM_REMOVE_SYSTEM_ARTIFACTS = 'remove system artifacts'


class MalwareLabel(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:MalwareLabelVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'adware',
        'appender',
        'backdoor',
        'boot sector virus',
        'bot',
        'clicker',
        'companion virus',
        'cavity filler',
        'data diddler',
        'downloader',
        'dropper file',
        'file infector virus',
        'fork bomb',
        'greyware',
        'implant',
        'infector',
        'keylogger',
        'kleptographic worm',
        'macro virus',
        'malcode',
        'mass-mailer',
        'metamorphic virus',
        'mid-infector',
        'mobile code',
        'multipartite virus',
        'password stealer',
        'polymorphic virus',
        'premium dialer/smser',
        'prepender',
        'ransomware',
        'rat',
        'rogue anti-malware',
        'rootkit',
        'shellcode',
        'spaghetti packer',
        'spyware',
        'trojan horse',
        'variant',
        'virus',
        'wabbit',
        'web bug',
        'wiper',
        'worm',
        'zip bomb',
    )
    TERM_DATA_DIDDLER = 'data diddler'
    TERM_PASSWORD_STEALER = 'password stealer'
    TERM_ADWARE = 'adware'
    TERM_WABBIT = 'wabbit'
    TERM_RANSOMWARE = 'ransomware'
    TERM_PREPENDER = 'prepender'
    TERM_MOBILE_CODE = 'mobile code'
    TERM_SPYWARE = 'spyware'
    TERM_WEB_BUG = 'web bug'
    TERM_RAT = 'rat'
    TERM_ROOTKIT = 'rootkit'
    TERM_COMPANION_VIRUS = 'companion virus'
    TERM_MACRO_VIRUS = 'macro virus'
    TERM_MALCODE = 'malcode'
    TERM_SHELLCODE = 'shellcode'
    TERM_ROGUE_ANTI_MALWARE = 'rogue anti-malware'
    TERM_FORK_BOMB = 'fork bomb'
    TERM_PREMIUM_DIALER_SMSER = 'premium dialer/smser'
    TERM_SPAGHETTI_PACKER = 'spaghetti packer'
    TERM_METAMORPHIC_VIRUS = 'metamorphic virus'
    TERM_POLYMORPHIC_VIRUS = 'polymorphic virus'
    TERM_BACKDOOR = 'backdoor'
    TERM_CLICKER = 'clicker'
    TERM_IMPLANT = 'implant'
    TERM_INFECTOR = 'infector'
    TERM_APPENDER = 'appender'
    TERM_BOOT_SECTOR_VIRUS = 'boot sector virus'
    TERM_MULTIPARTITE_VIRUS = 'multipartite virus'
    TERM_DOWNLOADER = 'downloader'
    TERM_VARIANT = 'variant'
    TERM_KEYLOGGER = 'keylogger'
    TERM_CAVITY_FILLER = 'cavity filler'
    TERM_VIRUS = 'virus'
    TERM_MASS_MAILER = 'mass-mailer'
    TERM_GREYWARE = 'greyware'
    TERM_MID_INFECTOR = 'mid-infector'
    TERM_KLEPTOGRAPHIC_WORM = 'kleptographic worm'
    TERM_WIPER = 'wiper'
    TERM_DROPPER_FILE = 'dropper file'
    TERM_ZIP_BOMB = 'zip bomb'
    TERM_BOT = 'bot'
    TERM_WORM = 'worm'
    TERM_FILE_INFECTOR_VIRUS = 'file infector virus'
    TERM_TROJAN_HORSE = 'trojan horse'


class SecurityDegradationProperties(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:SecurityDegradationPropertiesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'targeted program',
    )
    TERM_TARGETED_PROGRAM = 'targeted program'


class DiskActionName(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:DiskActionNameVocab-1.1'
    _VOCAB_VERSION = '1.1'
    _ALLOWED_VALUES = (
        'get disk type',
        'get disk attributes',
        'mount disk',
        'unmount disk',
        'emulate disk',
        'list disks',
        'monitor disk',
    )
    TERM_GET_DISK_ATTRIBUTES = 'get disk attributes'
    TERM_GET_DISK_TYPE = 'get disk type'
    TERM_MONITOR_DISK = 'monitor disk'
    TERM_MOUNT_DISK = 'mount disk'
    TERM_LIST_DISKS = 'list disks'
    TERM_EMULATE_DISK = 'emulate disk'
    TERM_UNMOUNT_DISK = 'unmount disk'


class IntegrityViolationTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:IntegrityViolationTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'subvert system',
        'corrupt system data',
        'annoy local system user',
        'intercept/manipulate network traffic',
        'annoy remote user',
        'corrupt user data',
    )
    TERM_SUBVERT_SYSTEM = 'subvert system'
    TERM_CORRUPT_SYSTEM_DATA = 'corrupt system data'
    TERM_ANNOY_LOCAL_SYSTEM_USER = 'annoy local system user'
    TERM_INTERCEPT_MANIPULATE_NETWORK_TRAFFIC = 'intercept/manipulate network traffic'
    TERM_ANNOY_REMOTE_USER = 'annoy remote user'
    TERM_CORRUPT_USER_DATA = 'corrupt user data'


class AntiDetectionTacticalObjectives(VocabString):
    _namespace = 'http://maec.mitre.org/default_vocabularies-1'
    _XSI_TYPE = 'maecVocabs:AntiDetectionTacticalObjectivesVocab-1.0'
    _VOCAB_VERSION = '1.0'
    _ALLOWED_VALUES = (
        'hide open network ports',
        'execute before/external to kernel/hypervisor',
        'encrypt self',
        'hide processes',
        'hide network traffic',
        'change/add content',
        'execute stealthy code',
        'hide registry artifacts',
        'hide userspace libraries',
        'hide arbitrary virtual memory',
        'execute non-main cpu code',
        'feed misinformation during physical memory acquisition',
        'prevent physical memory acquisition',
        'prevent native api hooking',
        'obfuscate artifact properties',
        'hide kernel modules',
        'hide code in file',
        'hide services',
        'hide file system artifacts',
        'hide threads',
    )
    TERM_HIDE_FILE_SYSTEM_ARTIFACTS = 'hide file system artifacts'
    TERM_HIDE_OPEN_NETWORK_PORTS = 'hide open network ports'
    TERM_EXECUTE_BEFORE_EXTERNAL_TO_KERNEL_HYPERVISOR = 'execute before/external to kernel/hypervisor'
    TERM_HIDE_KERNEL_MODULES = 'hide kernel modules'
    TERM_HIDE_PROCESSES = 'hide processes'
    TERM_CHANGE_ADD_CONTENT = 'change/add content'
    TERM_EXECUTE_STEALTHY_CODE = 'execute stealthy code'
    TERM_HIDE_REGISTRY_ARTIFACTS = 'hide registry artifacts'
    TERM_HIDE_USERSPACE_LIBRARIES = 'hide userspace libraries'
    TERM_HIDE_ARBITRARY_VIRTUAL_MEMORY = 'hide arbitrary virtual memory'
    TERM_EXECUTE_NON_MAIN_CPU_CODE = 'execute non-main cpu code'
    TERM_FEED_MISINFORMATION_DURING_PHYSICAL_MEMORY_ACQUISITION = 'feed misinformation during physical memory acquisition'
    TERM_PREVENT_PHYSICAL_MEMORY_ACQUISITION = 'prevent physical memory acquisition'
    TERM_PREVENT_NATIVE_API_HOOKING = 'prevent native api hooking'
    TERM_OBFUSCATE_ARTIFACT_PROPERTIES = 'obfuscate artifact properties'
    TERM_ENCRYPT_SELF = 'encrypt self'
    TERM_HIDE_SERVICES = 'hide services'
    TERM_HIDE_CODE_IN_FILE = 'hide code in file'
    TERM_HIDE_NETWORK_TRAFFIC = 'hide network traffic'
    TERM_HIDE_THREADS = 'hide threads'



#: Mapping of Controlled Vocabulary xsi:type's to their class implementations.
_VOCAB_MAP = {}


def add_vocab(cls):
    _VOCAB_MAP[cls._XSI_TYPE] = cls


add_vocab(DataTheftTacticalObjectives)
add_vocab(MachineAccessControlTacticalObjectives)
add_vocab(DataTheftProperties)
add_vocab(SecondaryOperationProperties)
add_vocab(SystemActionName)
add_vocab(AvailabilityViolationTacticalObjectives)
add_vocab(ActionObjectAssociationType)
add_vocab(CommonCapabilityProperties)
add_vocab(RemoteMachineManipulationTacticalObjectives)
add_vocab(PrivilegeEscalationStrategicObjectives)
add_vocab(DebuggingActionName)
add_vocab(DataExfiltrationStrategicObjectives)
add_vocab(DeviceDriverActionName)
add_vocab(ImportanceType)
add_vocab(HTTPActionName)
add_vocab(AntiDetectionStrategicObjectives)
add_vocab(SocketActionName)
add_vocab(CommandandControlTacticalObjectives)
add_vocab(HookingActionName)
add_vocab(GroupingRelationship)
add_vocab(PersistenceProperties)
add_vocab(DestructionProperties)
add_vocab(AntiCodeAnalysisStrategicObjectives)
add_vocab(AvailabilityViolationStrategicObjectives)
add_vocab(IPCActionName)
add_vocab(DirectoryActionName)
add_vocab(NetworkShareActionName)
add_vocab(InfectionPropagationProperties)
add_vocab(ProbingStrategicObjectives)
add_vocab(InfectionPropagationTacticalObjectives)
add_vocab(DataExfiltrationProperties)
add_vocab(LibraryActionName)
add_vocab(MalwareDevelopmentTool)
add_vocab(FileActionName)
add_vocab(CommandandControlProperties)
add_vocab(IRCActionName)
add_vocab(InfectionPropagationStrategicObjectives)
add_vocab(MalwareCapability)
add_vocab(AntiBehavioralAnalysisProperties)
add_vocab(DNSActionName)
add_vocab(RemoteMachineManipulationStrategicObjectives)
add_vocab(ProcessActionName)
add_vocab(PersistenceStrategicObjectives)
add_vocab(NetworkActionName)
add_vocab(SecondaryOperationStrategicObjectives)
add_vocab(FraudTacticalObjectives)
add_vocab(ProcessMemoryActionName)
add_vocab(RegistryActionName)
add_vocab(AvailabilityViolationProperties)
add_vocab(CommandandControlStrategicObjectives)
add_vocab(DestructionTacticalObjectives)
add_vocab(SpyingStrategicObjectives)
add_vocab(FTPActionName)
add_vocab(MachineAccessControlStrategicObjectives)
add_vocab(IntegrityViolationStrategicObjectives)
add_vocab(ProbingTacticalObjectives)
add_vocab(MalwareEntityType)
add_vocab(FraudStrategicObjectives)
add_vocab(SpyingTacticalObjectives)
add_vocab(ProcessThreadActionName)
add_vocab(DataTheftStrategicObjectives)
add_vocab(AntiCodeAnalysisTacticalObjectives)
add_vocab(PrivilegeEscalationTacticalObjectives)
add_vocab(MalwareSubjectRelationship)
add_vocab(AntiBehavioralAnalysisTacticalObjectives)
add_vocab(PersistenceTacticalObjectives)
add_vocab(SynchronizationActionName)
add_vocab(AntiRemovalTacticalObjectives)
add_vocab(SecurityDegradationStrategicObjectives)
add_vocab(PrivilegeEscalationProperties)
add_vocab(GUIActionName)
add_vocab(SecurityDegradationTacticalObjectives)
add_vocab(MalwareConfigurationParameter)
add_vocab(MachineAccessControlProperties)
add_vocab(ServiceActionName)
add_vocab(AntiBehavioralAnalysisStrategicObjectives)
add_vocab(CapabilityObjectiveRelationship)
add_vocab(DataExfiltrationTacticalObjectives)
add_vocab(UserActionName)
add_vocab(DestructionStrategicObjectives)
add_vocab(AntiRemovalStrategicObjectives)
add_vocab(SecondaryOperationTacticalObjectives)
add_vocab(MalwareLabel)
add_vocab(SecurityDegradationProperties)
add_vocab(DiskActionName)
add_vocab(IntegrityViolationTacticalObjectives)
add_vocab(AntiDetectionTacticalObjectives)
