#include "Wols_CA_OutlookInboxManager.hpp"
#include "resource.h" 
#include <shlobj.h>

// ==============================================================================
// Logger Implementation
// ==============================================================================
std::string Logger::m_filepath = "audit_log.txt";
LogLevel Logger::m_currentLevel = LogLevel::NORMAL;
std::mutex Logger::m_mutex;

void Logger::Initialize(const std::string& filepath , const std::string& levelStr)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_filepath = filepath;
    m_currentLevel = ( levelStr == "DEBUG" ) ? LogLevel::DEBUG_LEVEL : LogLevel::NORMAL;
    std::ofstream file(m_filepath , std::ios::out | std::ios::trunc);
    if ( file.is_open( ) ) file << "[" << GetCurrentDateTime( ) << "] [INFO] Logger initialized." << std::endl;
}
std::string Logger::GetCurrentDateTime( )
{
    auto now = std::chrono::system_clock::now( );
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss; struct tm timeInfo;
    if ( localtime_s(&timeInfo , &in_time_t) == 0 ) ss << std::put_time(&timeInfo , "%Y-%m-%d %H:%M:%S");
    return ss.str( );
}
void Logger::LogAction(const std::string& actionName , bool isFinished)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream file(m_filepath , std::ios::out | std::ios::app);
    if ( file.is_open( ) ) file << "[" << GetCurrentDateTime( ) << "] [ACTION] " << actionName << " -> " << ( isFinished ? "FINISHED" : "START" ) << std::endl;
}
void Logger::LogDebug(const std::string& message)
{
    if ( m_currentLevel != LogLevel::DEBUG_LEVEL ) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream file(m_filepath , std::ios::out | std::ios::app);
    if ( file.is_open( ) ) file << "[" << GetCurrentDateTime( ) << "] [DEBUG] " << message << std::endl;
}

// ==============================================================================
// ConfigManager
// ==============================================================================
ConfigManager::ConfigManager(const std::string& configFilePath) : m_configFile(configFilePath)
{
    LoadConfig( );
}
void ConfigManager::LoadConfig( )
{
    try
    {
        std::ifstream file(m_configFile); if ( file.is_open( ) ) file >> m_data;
    }
    catch ( ... )
    {
    }
}
std::wstring ConfigManager::Utf8ToWstring(const std::string& str) const
{
    if ( str.empty( ) ) return std::wstring( );
    int size_needed = MultiByteToWideChar(CP_UTF8 , 0 , &str[ 0 ] , ( int ) str.size( ) , NULL , 0);
    std::wstring wstrTo(size_needed , 0);
    MultiByteToWideChar(CP_UTF8 , 0 , &str[ 0 ] , ( int ) str.size( ) , &wstrTo[ 0 ] , size_needed);
    return wstrTo;
}
std::wstring ConfigManager::GetText(const std::string& key) const
{
    if ( m_data.contains(key) ) return Utf8ToWstring(m_data[ key ].get<std::string>( ));
    return Utf8ToWstring("[" + key + "]");
}
std::string ConfigManager::GetConfigString(const std::string& key) const
{
    if ( m_data.contains("config") && m_data[ "config" ].contains(key) ) return m_data[ "config" ][ key ].get<std::string>( );
    return "";
}
int ConfigManager::GetConfigInt(const std::string& key) const
{
    if ( m_data.contains("config") && m_data[ "config" ].contains(key) ) return m_data[ "config" ][ key ].get<int>( );
    return 0;
}
bool ConfigManager::GetConfigBool(const std::string& key) const
{
    if ( m_data.contains("config") && m_data[ "config" ].contains(key) ) return m_data[ "config" ][ key ].get<bool>( );
    return false;
}
std::vector<std::string> ConfigManager::GetConfigArray(const std::string& key) const
{
    std::vector<std::string> result;
    if ( m_data.contains("config") && m_data[ "config" ].contains(key) )
    {
        for ( const auto& item : m_data[ "config" ][ key ] ) result.push_back(item.get<std::string>( ));
    }
    return result;
}

// ==============================================================================
// RulesManager 
// ==============================================================================
RulesManager::RulesManager(const std::string& rulesFilePath) : m_rulesFile(rulesFilePath)
{
    LoadRules( );
}
void RulesManager::LoadRules( )
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ruleMap.clear( ); m_sessionNewSenders.clear( );
    std::ifstream file(m_rulesFile);
    if ( file.is_open( ) )
    {
        try
        {
            nlohmann::json rulesJson; file >> rulesJson;
            for ( auto& [folder , emails] : rulesJson.items( ) )
            {
                if ( emails.is_array( ) )
                {
                    for ( const auto& email : emails ) m_ruleMap[ email.get<std::string>( ) ] = folder;
                }
            }
        }
        catch ( ... )
        {
        }
    }
}
void RulesManager::AddRuleInMemory(const std::string& senderAddress , const std::string& folderPath)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if ( m_ruleMap.find(senderAddress) == m_ruleMap.end( ) )
    {
        m_sessionNewSenders.insert(senderAddress);
    }
    m_ruleMap[ senderAddress ] = folderPath;
}
void RulesManager::SaveRule(const std::string& senderAddress , const std::string& folderPath)
{
    AddRuleInMemory(senderAddress , folderPath); SaveAllRules( );
}
void RulesManager::SaveAllRules( )
{
    std::lock_guard<std::mutex> lock(m_mutex);
    nlohmann::json outJson;
    for ( const auto& pair : m_ruleMap ) outJson[ pair.second ].push_back(pair.first);
    for ( auto& [folder , emails] : outJson.items( ) ) std::sort(emails.begin( ) , emails.end( ));
    std::ofstream file(m_rulesFile);
    if ( file.is_open( ) ) file << outJson.dump(4);
}
std::string RulesManager::GetRule(const std::string& senderAddress) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_ruleMap.find(senderAddress);
    return ( it != m_ruleMap.end( ) ) ? it->second : "";
}
bool RulesManager::IsNewSessionSender(const std::string& senderAddress) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_sessionNewSenders.find(senderAddress) != m_sessionNewSenders.end( );
}

// ==============================================================================
// WindowManager
// ==============================================================================
WindowManager::WindowManager( )
{
    m_screenWidth = GetSystemMetrics(SM_CXSCREEN); m_screenHeight = GetSystemMetrics(SM_CYSCREEN);
}
void WindowManager::LaunchAndArrange(const std::wstring& outlookPath , const std::wstring& chromePath)
{
    STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi;
    if ( CreateProcessW(outlookPath.c_str( ) , NULL , NULL , NULL , FALSE , 0 , NULL , NULL , &si , &pi) )
    {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    if ( CreateProcessW(chromePath.c_str( ) , NULL , NULL , NULL , FALSE , 0 , NULL , NULL , &si , &pi) )
    {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

// ==============================================================================
// OutlookManager COM Engine
// ==============================================================================
OutlookManager::OutlookManager(ConfigManager* config , RulesManager* rules) : m_config(config) , m_rules(rules)
{
    m_downloadDir = m_config->GetConfigString("download_directory");
    InitializeCOM( ); EnsureDownloadDirExists( );
}
OutlookManager::~OutlookManager( )
{
    m_mapiNamespace.Release( ); m_outlookApp.Release( ); CoUninitialize( );
}
void OutlookManager::InitializeCOM( )
{
    HRESULT hr = CoInitializeEx(NULL , COINIT_APARTMENTTHREADED);
    if ( FAILED(hr) ) return;
    CLSID clsid;
    if ( SUCCEEDED(CLSIDFromProgID(L"Outlook.Application" , &clsid)) )
    {
        if ( SUCCEEDED(CoCreateInstance(clsid , NULL , CLSCTX_LOCAL_SERVER , IID_IDispatch , ( void** ) &m_outlookApp)) )
        {
            CComVariant result , arg(L"MAPI"); DISPPARAMS params = { &arg, NULL, 1, 0 };
            if ( SUCCEEDED(InvokeMethod(m_outlookApp , L"GetNamespace" , DISPATCH_METHOD , &result , &params)) && result.vt == VT_DISPATCH )
            {
                m_mapiNamespace = result.pdispVal;
            }
        }
    }
}
HRESULT OutlookManager::InvokeMethod(IDispatch* pDisp , LPCOLESTR name , WORD wFlags , VARIANT* pVarResult , DISPPARAMS* pParams)
{
    DISPID dispid; LPOLESTR nonConstName = const_cast< LPOLESTR >( name );
    HRESULT hr = pDisp->GetIDsOfNames(IID_NULL , &nonConstName , 1 , LOCALE_USER_DEFAULT , &dispid);
    if ( FAILED(hr) ) return hr;
    return pDisp->Invoke(dispid , IID_NULL , LOCALE_USER_DEFAULT , wFlags , pParams , pVarResult , NULL , NULL);
}
CComVariant OutlookManager::GetProperty(IDispatch* pDisp , LPCOLESTR name)
{
    CComVariant result; DISPPARAMS params = { NULL, NULL, 0, 0 };
    InvokeMethod(pDisp , name , DISPATCH_PROPERTYGET , &result , &params);
    return result;
}
HRESULT OutlookManager::PutProperty(IDispatch* pDisp , LPCOLESTR name , VARIANT* pVar)
{
    DISPID dispid; LPOLESTR nonConstName = const_cast< LPOLESTR >( name );
    HRESULT hr = pDisp->GetIDsOfNames(IID_NULL , &nonConstName , 1 , LOCALE_USER_DEFAULT , &dispid);
    if ( FAILED(hr) ) return hr;
    DISPPARAMS params = { pVar, NULL, 1, 0 };
    DISPID dispidNamed = DISPID_PROPERTYPUT;
    params.cNamedArgs = 1; params.rgdispidNamedArgs = &dispidNamed;
    return pDisp->Invoke(dispid , IID_NULL , LOCALE_USER_DEFAULT , DISPATCH_PROPERTYPUT , &params , NULL , NULL , NULL);
}
void OutlookManager::EnsureDownloadDirExists( )
{
    if ( m_downloadDir.empty( ) ) return;
    std::filesystem::path dir(m_downloadDir);
    if ( !dir.is_absolute( ) )
    {
        PWSTR downloadsPath = NULL;
        if ( SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads , 0 , NULL , &downloadsPath)) )
        {
            std::filesystem::path baseDir(downloadsPath); CoTaskMemFree(downloadsPath); dir = baseDir / dir;
        }
    }
    m_downloadDir = dir.string( );
    std::error_code ec;
    if ( !std::filesystem::exists(dir , ec) && !ec ) std::filesystem::create_directories(dir , ec);
}
CComPtr<IDispatch> OutlookManager::GetInbox( )
{
    if ( !m_mapiNamespace ) return nullptr;
    CComVariant result , arg(6); DISPPARAMS params = { &arg, NULL, 1, 0 };
    if ( SUCCEEDED(InvokeMethod(m_mapiNamespace , L"GetDefaultFolder" , DISPATCH_METHOD , &result , &params)) && result.vt == VT_DISPATCH ) return result.pdispVal;
    return nullptr;
}
CComPtr<IDispatch> OutlookManager::EnsureFolderExists(CComPtr<IDispatch> parentFolder , const std::wstring& folderName)
{
    if ( !parentFolder ) return nullptr;
    CComVariant foldersVar = GetProperty(parentFolder , L"Folders");
    if ( foldersVar.vt != VT_DISPATCH || !foldersVar.pdispVal ) return nullptr;
    CComPtr<IDispatch> folders = foldersVar.pdispVal;
    CComVariant nameArg(folderName.c_str( )); DISPPARAMS itemParams = { &nameArg, NULL, 1, 0 }; CComVariant folderVar;
    if ( SUCCEEDED(InvokeMethod(folders , L"Item" , DISPATCH_METHOD , &folderVar , &itemParams)) && folderVar.vt == VT_DISPATCH && folderVar.pdispVal ) return folderVar.pdispVal;
    DISPPARAMS addParams = { &nameArg, NULL, 1, 0 }; CComVariant newFolderVar;
    if ( SUCCEEDED(InvokeMethod(folders , L"Add" , DISPATCH_METHOD , &newFolderVar , &addParams)) && newFolderVar.vt == VT_DISPATCH ) return newFolderVar.pdispVal;
    return nullptr;
}
std::string OutlookManager::GetSenderAddress(CComPtr<IDispatch> mailItem)
{
    CComVariant senderProp = GetProperty(mailItem , L"SenderEmailAddress");
    if ( senderProp.vt == VT_BSTR && senderProp.bstrVal != nullptr )
    {
        std::wstring wSender(senderProp.bstrVal);
        int size = WideCharToMultiByte(CP_UTF8 , 0 , wSender.c_str( ) , -1 , NULL , 0 , NULL , NULL);
        if ( size > 0 )
        {
            std::string sSender(size , 0);
            WideCharToMultiByte(CP_UTF8 , 0 , wSender.c_str( ) , -1 , &sSender[ 0 ] , size , NULL , NULL);
            if ( !sSender.empty( ) && sSender.back( ) == '\0' ) sSender.pop_back( );
            return sSender;
        }
    }
    return "";
}
std::string OutlookManager::GetMailBody(CComPtr<IDispatch> mailItem)
{
    CComVariant bodyProp = GetProperty(mailItem , L"Body");
    if ( bodyProp.vt == VT_BSTR && bodyProp.bstrVal != nullptr )
    {
        std::wstring wBody(bodyProp.bstrVal);
        int size = WideCharToMultiByte(CP_UTF8 , 0 , wBody.c_str( ) , -1 , NULL , 0 , NULL , NULL);
        if ( size > 0 )
        {
            std::string sBody(size , 0);
            WideCharToMultiByte(CP_UTF8 , 0 , wBody.c_str( ) , -1 , &sBody[ 0 ] , size , NULL , NULL);
            return sBody;
        }
    }
    return "";
}
bool OutlookManager::HasAttachments(CComPtr<IDispatch> mailItem)
{
    CComVariant attVar = GetProperty(mailItem , L"Attachments");
    if ( attVar.vt == VT_DISPATCH && attVar.pdispVal )
    {
        CComVariant countVar = GetProperty(attVar.pdispVal , L"Count");
        if ( countVar.vt == VT_I4 && countVar.lVal > 0 ) return true;
    }
    return false;
}
bool OutlookManager::ContainsPrices(const std::string& text)
{
    std::string regexStr = m_config->GetConfigString("price_regex");
    if ( regexStr.empty( ) ) return false;
    try
    {
        std::regex priceRegex(regexStr);
        return std::regex_search(text , priceRegex);
    }
    catch ( ... )
    {
        return false;
    }
}

// Check de platte JSON arrays voor multi-taal keywords
bool OutlookManager::ContainsKeywords(const std::string& text , const std::vector<std::string>& keywords)
{
    std::string lowerText = text;
    std::transform(lowerText.begin( ) , lowerText.end( ) , lowerText.begin( ) , ::tolower);
    for ( const auto& kw : keywords )
    {
        std::string lowerKw = kw;
        std::transform(lowerKw.begin( ) , lowerKw.end( ) , lowerKw.begin( ) , ::tolower);
        if ( lowerText.find(lowerKw) != std::string::npos ) return true;
    }
    return false;
}

void OutlookManager::SetCategory(CComPtr<IDispatch> mailItem , const std::string& categoryName)
{
    if ( categoryName.empty( ) ) return;
    std::wstring wCat = m_config->Utf8ToWstring(categoryName);
    CComVariant catVar(wCat.c_str( ));
    PutProperty(mailItem , L"Categories" , &catVar);
    DISPPARAMS saveParams = { NULL, NULL, 0, 0 }; CComVariant saveResult;
    InvokeMethod(mailItem , L"Save" , DISPATCH_METHOD , &saveResult , &saveParams);
}
void OutlookManager::SetFlagForProcess(CComPtr<IDispatch> mailItem , int daysFromNow)
{
    CComVariant markFlag(2);
    DISPPARAMS flagParams = { &markFlag, NULL, 1, 0 }; CComVariant flagResult;
    InvokeMethod(mailItem , L"MarkAsTask" , DISPATCH_METHOD , &flagResult , &flagParams);
    DISPPARAMS saveParams = { NULL, NULL, 0, 0 }; CComVariant saveResult;
    InvokeMethod(mailItem , L"Save" , DISPATCH_METHOD , &saveResult , &saveParams);
}
std::string OutlookManager::GetFolderName(CComPtr<IDispatch> folder)
{
    CComVariant nameProp = GetProperty(folder , L"Name");
    if ( nameProp.vt == VT_BSTR && nameProp.bstrVal != nullptr )
    {
        std::wstring wName(nameProp.bstrVal);
        int size = WideCharToMultiByte(CP_UTF8 , 0 , wName.c_str( ) , -1 , NULL , 0 , NULL , NULL);
        if ( size > 0 )
        {
            std::string sName(size , 0);
            WideCharToMultiByte(CP_UTF8 , 0 , wName.c_str( ) , -1 , &sName[ 0 ] , size , NULL , NULL);
            if ( !sName.empty( ) && sName.back( ) == '\0' ) sName.pop_back( );
            return sName;
        }
    }
    return "";
}

// ==============================================================================
// PHASE 2 - Process Inbox (De Werkelijke Verwerking)
// ==============================================================================
void OutlookManager::ProcessInbox( )
{
    Logger::LogAction("ProcessInbox" , false);
    CComPtr<IDispatch> inbox = GetInbox( );
    if ( !inbox )
    {
        Logger::LogAction("ProcessInbox" , true); return;
    }

    CComVariant itemsVar = GetProperty(inbox , L"Items");
    if ( itemsVar.vt != VT_DISPATCH || !itemsVar.pdispVal ) return;
    CComPtr<IDispatch> items = itemsVar.pdispVal;

    CComPtr<IDispatch> workingItems = items;
    if ( m_config->GetConfigBool("process_unread_only") )
    {
        Logger::LogDebug("Filter actief: Controleert uitsluitend Ongelezen (Unread) e-mails.");
        CComVariant query(L"[UnRead] = True");
        DISPPARAMS resParams = { &query, NULL, 1, 0 }; CComVariant restrictedItems;
        if ( SUCCEEDED(InvokeMethod(items , L"Restrict" , DISPATCH_METHOD , &restrictedItems , &resParams)) && restrictedItems.vt == VT_DISPATCH )
        {
            workingItems = restrictedItems.pdispVal;
        }
    }

    CComVariant countVar = GetProperty(workingItems , L"Count");
    if ( countVar.vt != VT_I4 ) return;
    long count = countVar.lVal;

    std::vector<std::string> invoiceKeys = m_config->GetConfigArray("invoice_keywords");
    std::vector<std::string> orderKeys = m_config->GetConfigArray("order_keywords");

    for ( long i = count; i >= 1; --i )
    {
        CComVariant index(i); DISPPARAMS params = { &index, NULL, 1, 0 }; CComVariant itemVar;
        if ( SUCCEEDED(InvokeMethod(workingItems , L"Item" , DISPATCH_METHOD , &itemVar , &params)) && itemVar.vt == VT_DISPATCH )
        {
            CComPtr<IDispatch> mailItem = itemVar.pdispVal;
            std::string sender = GetSenderAddress(mailItem);
            if ( sender.empty( ) ) continue;

            std::string targetFolderName = m_rules->GetRule(sender);
            std::string body = GetMailBody(mailItem);

            // 1. Onbekende afzender -> Quarantaine
            if ( targetFolderName.empty( ) )
            {
                Logger::LogDebug("Nieuw adres: " + sender + ". Routeer naar _New Address en tag Groen.");
                SetCategory(mailItem , m_config->GetConfigString("category_new_first_green"));
                targetFolderName = m_config->GetConfigString("folder_new_address");
            }
            // 2. Bekende Contacten
            else if ( targetFolderName == m_config->GetConfigString("folder_contacten") )
            {
                Logger::LogDebug("Contact gedetecteerd: " + sender + ". Routeer direct naar _Contacten zonder factuurcontrole.");
            }
            // 3. Bekende Bedrijven (Inkoop / Order detectie)
            else
            {
                if ( m_rules->IsNewSessionSender(sender) )
                {
                    SetCategory(mailItem , m_config->GetConfigString("category_new_session_lightgreen"));
                }

                // Controleer op Facturen
                if ( ContainsKeywords(body , invoiceKeys) )
                {
                    targetFolderName = m_config->GetConfigString("folder_purchasing"); // Forceer naar Inkoop
                    SetFlagForProcess(mailItem , 2);
                    Logger::LogDebug("Factuur herkend voor " + sender + ". Vlag gezet en routeer naar " + targetFolderName);
                }
                // Controleer op Orders / Prijzen
                else if ( ContainsKeywords(body , orderKeys) || ContainsPrices(body) )
                {
                    // Verplaats naar de normale bedrijfsmap, maar markeer eventueel
                    Logger::LogDebug("Order/Prijs herkend voor " + sender + ". Routeer naar bedrijfsmap: " + targetFolderName);
                }
                // Geen herkenning en geen bijlage -> Visuele check nodig
                else if ( !HasAttachments(mailItem) )
                {
                    Logger::LogDebug("Geen bijlage & Geen factuurwoorden voor " + sender + ". Flag Check (Oranje).");
                    SetCategory(mailItem , m_config->GetConfigString("category_check_orange"));
                }
            }

            // Voer de fysieke verplaatsing uit
            if ( !targetFolderName.empty( ) )
            {
                std::wstring wFolderName = m_config->Utf8ToWstring(targetFolderName);
                CComPtr<IDispatch> targetFolder = EnsureFolderExists(inbox , wFolderName);
                if ( targetFolder )
                {
                    CComVariant folderArg(targetFolder); DISPPARAMS moveParams = { &folderArg, NULL, 1, 0 }; CComVariant moveResult;
                    InvokeMethod(mailItem , L"Move" , DISPATCH_METHOD , &moveResult , &moveParams);
                }
            }
        }
    }
    Logger::LogAction("ProcessInbox" , true);
}


// ==============================================================================
// PHASE 1: Audit Folders - Uitlezen en Configureren
// ==============================================================================
void OutlookManager::AuditFolders( )
{
    Logger::LogAction("AuditFolders" , false);
    CComPtr<IDispatch> inbox = GetInbox( );
    if ( !inbox ) return;

    CComVariant foldersVar = GetProperty(inbox , L"Folders");
    if ( foldersVar.vt != VT_DISPATCH || !foldersVar.pdispVal ) return;
    CComPtr<IDispatch> folders = foldersVar.pdispVal;

    CComVariant folderCountVar = GetProperty(folders , L"Count");
    if ( folderCountVar.vt != VT_I4 ) return;
    long folderCount = folderCountVar.lVal;

    for ( long f = 1; f <= folderCount; ++f )
    {
        CComVariant fIndex(f); DISPPARAMS fParams = { &fIndex, NULL, 1, 0 }; CComVariant folderVar;
        if ( SUCCEEDED(InvokeMethod(folders , L"Item" , DISPATCH_METHOD , &folderVar , &fParams)) && folderVar.vt == VT_DISPATCH )
        {
            CComPtr<IDispatch> currentFolder = folderVar.pdispVal;
            std::string currentFolderName = GetFolderName(currentFolder);

            CComVariant itemsVar = GetProperty(currentFolder , L"Items");
            if ( itemsVar.vt == VT_DISPATCH && itemsVar.pdispVal )
            {
                CComPtr<IDispatch> items = itemsVar.pdispVal;

                CComPtr<IDispatch> workingItems = items;
                if ( m_config->GetConfigBool("process_unread_only") )
                {
                    CComVariant query(L"[UnRead] = True"); DISPPARAMS resParams = { &query, NULL, 1, 0 }; CComVariant restrictedItems;
                    if ( SUCCEEDED(InvokeMethod(items , L"Restrict" , DISPATCH_METHOD , &restrictedItems , &resParams)) && restrictedItems.vt == VT_DISPATCH )
                    {
                        workingItems = restrictedItems.pdispVal;
                    }
                }

                CComVariant itemCountVar = GetProperty(workingItems , L"Count");
                if ( itemCountVar.vt == VT_I4 )
                {
                    long itemCount = itemCountVar.lVal;
                    for ( long i = 1; i <= itemCount; ++i )
                    {
                        CComVariant iIndex(i); DISPPARAMS iParams = { &iIndex, NULL, 1, 0 }; CComVariant itemVar;
                        if ( SUCCEEDED(InvokeMethod(workingItems , L"Item" , DISPATCH_METHOD , &itemVar , &iParams)) && itemVar.vt == VT_DISPATCH )
                        {
                            std::string sender = GetSenderAddress(itemVar.pdispVal);
                            if ( sender.empty( ) ) continue;

                            std::string expectedFolder = m_rules->GetRule(sender);

                            if ( currentFolderName == m_config->GetConfigString("folder_contacten") ||
                                currentFolderName == m_config->GetConfigString("folder_new_to_process") )
                            {
                                if ( expectedFolder.empty( ) || expectedFolder == m_config->GetConfigString("folder_new_address") )
                                {
                                    m_rules->AddRuleInMemory(sender , currentFolderName);
                                    Logger::LogDebug("Leermodus: Regel aangemaakt via drag-and-drop [" + sender + "] -> [" + currentFolderName + "]");
                                }
                            } else if ( expectedFolder.empty( ) )
                            {
                                m_rules->AddRuleInMemory(sender , currentFolderName);
                            } else if ( expectedFolder != currentFolderName )
                            {
                                Logger::LogDebug("Email van [" + sender + "] staat in [" + currentFolderName + "] maar hoort in [" + expectedFolder + "] *** Missplaced eMail *** ");
                            }
                        }
                    }
                }
            }
        }
    }
    m_rules->SaveAllRules( );
    Logger::LogAction("AuditFolders" , true);
}


// ... UIManager en wWinMain ...
UIManager::UIManager(ConfigManager* config , OutlookManager* outlook) : m_config(config) , m_outlookManager(outlook) , m_hwnd(NULL)
{
    ZeroMemory(&m_nid , sizeof(m_nid));
}
UIManager::~UIManager( )
{
    StopTray( );
}
LRESULT CALLBACK UIManager::WindowProc(HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam)
{
    UIManager* pThis = nullptr;
    if ( uMsg == WM_NCCREATE )
    {
        CREATESTRUCT* pCreate = ( CREATESTRUCT* ) lParam; pThis = ( UIManager* ) pCreate->lpCreateParams; SetWindowLongPtr(hwnd , GWLP_USERDATA , ( LONG_PTR ) pThis);
    } else
    {
        pThis = ( UIManager* ) GetWindowLongPtr(hwnd , GWLP_USERDATA);
    }
    if ( pThis )
    {
        if ( uMsg == WM_USER + 1 )
        {
            if ( lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP )
            {
                POINT pt; GetCursorPos(&pt); pThis->ShowContextMenu(hwnd , pt);
            }
        } else if ( uMsg == WM_COMMAND )
        {
            int wmId = LOWORD(wParam);
            switch ( wmId )
            {
                case 1001: pThis->ShowNotification(L"Wols CA" , L"Inbox wordt verwerkt..."); pThis->m_outlookManager->ProcessInbox( ); pThis->ShowNotification(L"Wols CA" , L"Verwerking voltooid!"); break;
                case 1002: pThis->ShowNotification(L"Wols CA" , L"Mappenstructuur wordt gecontroleerd..."); pThis->m_outlookManager->AuditFolders( ); pThis->ShowNotification(L"Wols CA" , L"Audit voltooid!"); break;
                case 1003: ShellExecuteW(NULL , L"open" , L"Wols_CA_InboxManagerLanguage.json" , NULL , NULL , SW_SHOW); break;
                case 1004: PostQuitMessage(0); break;
            }
        }
    } return DefWindowProc(hwnd , uMsg , wParam , lParam);
}
void UIManager::ShowNotification(const std::wstring& title , const std::wstring& message)
{
    m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO; wcsncpy_s(m_nid.szInfoTitle , title.c_str( ) , _TRUNCATE); wcsncpy_s(m_nid.szInfo , message.c_str( ) , _TRUNCATE); m_nid.dwInfoFlags = NIIF_INFO; m_nid.uTimeout = 3000; Shell_NotifyIconW(NIM_MODIFY , &m_nid);
}
void UIManager::StartTray( )
{
    const wchar_t CLASS_NAME [ ] = L"WolsCA_HiddenWindow"; WNDCLASSW wc = {}; wc.lpfnWndProc = UIManager::WindowProc; wc.hInstance = GetModuleHandle(NULL); wc.lpszClassName = CLASS_NAME; RegisterClassW(&wc);
    m_hwnd = CreateWindowExW(0 , CLASS_NAME , L"TrayWindow" , 0 , 0 , 0 , 0 , 0 , HWND_MESSAGE , NULL , wc.hInstance , this);
    m_nid.cbSize = sizeof(NOTIFYICONDATAW); m_nid.hWnd = m_hwnd; m_nid.uID = 1; m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; m_nid.uCallbackMessage = WM_USER + 1;
    HICON hEmbeddedIcon = ( HICON ) LoadImageW(GetModuleHandle(NULL) , MAKEINTRESOURCEW(101) , IMAGE_ICON , 0 , 0 , LR_DEFAULTSIZE | LR_SHARED);
    m_nid.hIcon = hEmbeddedIcon ? hEmbeddedIcon : LoadIcon(NULL , IDI_APPLICATION);
    wcsncpy_s(m_nid.szTip , m_config->GetText("tray_tooltip").c_str( ) , _TRUNCATE); Shell_NotifyIconW(NIM_ADD , &m_nid);
    MSG msg; while ( GetMessage(&msg , NULL , 0 , 0) )
    {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
}
void UIManager::ShowContextMenu(HWND hwnd , POINT pt)
{
    HMENU hMenu = CreatePopupMenu( );
    AppendMenuW(hMenu , MF_STRING , 1001 , m_config->GetText("menu_process_now").c_str( ));
    AppendMenuW(hMenu , MF_STRING , 1002 , m_config->GetText("menu_audit").c_str( ));
    AppendMenuW(hMenu , MF_SEPARATOR , 0 , NULL); AppendMenuW(hMenu , MF_STRING , 1003 , m_config->GetText("menu_config").c_str( ));
    AppendMenuW(hMenu , MF_SEPARATOR , 0 , NULL); AppendMenuW(hMenu , MF_STRING , 1004 , m_config->GetText("menu_quit").c_str( ));
    SetForegroundWindow(hwnd); TrackPopupMenu(hMenu , TPM_BOTTOMALIGN | TPM_LEFTALIGN , pt.x , pt.y , 0 , hwnd , NULL); DestroyMenu(hMenu);
}
void UIManager::StopTray( )
{
    Shell_NotifyIconW(NIM_DELETE , &m_nid); if ( m_hwnd ) DestroyWindow(m_hwnd);
}
void BackgroundWorker(ConfigManager* config , OutlookManager* /* outlook */)
{
    int pollInterval = config->GetConfigInt("poll_interval_seconds");
    while ( true )
    {
        std::this_thread::sleep_for(std::chrono::seconds(pollInterval));
    }
}
int WINAPI wWinMain(HINSTANCE hInstance , HINSTANCE hPrevInstance , PWSTR pCmdLine , int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance); UNREFERENCED_PARAMETER(hPrevInstance); UNREFERENCED_PARAMETER(pCmdLine); UNREFERENCED_PARAMETER(nCmdShow);
    char exePath[ MAX_PATH ]; GetModuleFileNameA(NULL , exePath , MAX_PATH); std::filesystem::path fullPath(exePath); std::string dynamicLogFileName = fullPath.stem( ).string( ) + ".log";
    ConfigManager config("Wols_CA_InboxManagerLanguage.json"); RulesManager rules(config.GetConfigString("rules_file"));
    Logger::Initialize(dynamicLogFileName , config.GetConfigString("log_level"));
    WindowManager wm; wm.LaunchAndArrange(config.Utf8ToWstring(config.GetConfigString("outlook_path")) , config.Utf8ToWstring(config.GetConfigString("chrome_path")));
    OutlookManager outlook(&config , &rules); UIManager ui(&config , &outlook);
    std::thread monitorThread(BackgroundWorker , &config , &outlook); monitorThread.detach( );
    ui.StartTray( );
    return 0;
}