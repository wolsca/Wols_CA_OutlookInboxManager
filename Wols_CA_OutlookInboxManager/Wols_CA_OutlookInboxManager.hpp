#pragma once

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <atlbase.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <regex>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include <nlohmann/json.hpp>

enum class LogLevel
{
    NORMAL , DEBUG_LEVEL
};

class Logger
{
public:
    static void Initialize(const std::string& filepath , const std::string& levelStr);
    static void LogAction(const std::string& actionName , bool isFinished);
    static void LogDebug(const std::string& message);
private:
    static std::string m_filepath;
    static LogLevel m_currentLevel;
    static std::mutex m_mutex;
    static std::string GetCurrentDateTime( );
};

class ConfigManager
{
public:
    ConfigManager(const std::string& configFilePath);
    std::wstring GetText(const std::string& key) const;
    std::string GetConfigString(const std::string& key) const;
    int GetConfigInt(const std::string& key) const;
    bool GetConfigBool(const std::string& key) const;
    std::vector<std::string> GetConfigArray(const std::string& key) const;
    std::wstring Utf8ToWstring(const std::string& str) const;
private:
    std::string m_configFile;
    nlohmann::json m_data;
    void LoadConfig( );
};

class RulesManager
{
public:
    RulesManager(const std::string& rulesFilePath);
    void LoadRules( );
    void SaveRule(const std::string& senderAddress , const std::string& folderPath);
    void AddRuleInMemory(const std::string& senderAddress , const std::string& folderPath);
    void SaveAllRules( );
    std::string GetRule(const std::string& senderAddress) const;
    bool IsNewSessionSender(const std::string& senderAddress) const;

private:
    std::string m_rulesFile;
    std::map<std::string , std::string> m_ruleMap;
    std::unordered_set<std::string> m_sessionNewSenders;
    mutable std::mutex m_mutex;
};

class WindowManager
{
public:
    WindowManager( );
    void LaunchAndArrange(const std::wstring& outlookPath , const std::wstring& chromePath);
private:
    int m_screenWidth;
    int m_screenHeight;
    void PositionWindowByTitle(const std::wstring& titleKeyword , int x , int y , int w , int h);
    static BOOL CALLBACK EnumWindowsProc(HWND hwnd , LPARAM lParam);
};

class OutlookManager
{
public:
    OutlookManager(ConfigManager* config , RulesManager* rules);
    ~OutlookManager( );

    void ProcessInbox( );
    void AuditFolders( );

private:
    ConfigManager* m_config;
    RulesManager* m_rules;
    std::string m_downloadDir;

    CComPtr<IDispatch> m_outlookApp;
    CComPtr<IDispatch> m_mapiNamespace;

    void InitializeCOM( );
    void EnsureDownloadDirExists( );
    CComPtr<IDispatch> GetInbox( );
    CComPtr<IDispatch> EnsureFolderExists(CComPtr<IDispatch> parentFolder , const std::wstring& folderName);

    std::string GetSenderAddress(CComPtr<IDispatch> mailItem);
    std::string GetFolderName(CComPtr<IDispatch> folder);
    std::string GetMailBody(CComPtr<IDispatch> mailItem);
    bool HasAttachments(CComPtr<IDispatch> mailItem);
    bool ContainsPrices(const std::string