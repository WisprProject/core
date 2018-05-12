// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Wispr Test Suite

#include "main.h"
#include "random.h"
#include "txdb.h"
#include "ui_interface.h"
#include "util.h"

#ifdef ENABLE_WALLET
#include "db.h"
#include "wallet.h"
#endif

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

CClientUIInterface uiInterface;
CWallet *pwalletMain;

extern bool fPrintToConsole;

extern void noui_connect();
struct TestingSetup {
    CCoinsViewDB *pcoinsdbview;
    boost::filesystem::path pathTemp;
    boost::thread_group threadGroup;
    TestingSetup() {
        SetupEnvironment();
        cout << "Finished setup environment...\n";
        fPrintToDebugLog = false; // don't want to write to debug.log file
        fCheckBlockIndex = true;
        cout << "Select params...\n";
        SelectParams(CBaseChainParams::UNITTEST);
        cout << "Connect noui...\n";
        noui_connect();
#ifdef ENABLE_WALLET
        bitdb.MakeMock();
#endif
        pathTemp = GetTempPath() / strprintf("test_wispr_%lu_%i", (unsigned long) GetTime(), (int) (GetRand(100000)));
        cout << "Create Directories...\n";
        boost::filesystem::create_directories(pathTemp);
        mapArgs["-datadir"] = pathTemp.string();
        cout << "Create BlockTreeDB...\n";
        pblocktree = new CBlockTreeDB(1 << 20, true);
        cout << "Create CoinsViewDB...\n";
        pcoinsdbview = new CCoinsViewDB(1 << 23, true);
        cout << "Create CoinsViewCache...\n";
        pcoinsTip = new CCoinsViewCache(pcoinsdbview);
        cout << "Init block index...\n";
        InitBlockIndex();
#ifdef ENABLE_WALLET
        bool fFirstRun;
        cout << "Create wallet...\n";
        pwalletMain = new CWallet("wallet.dat");
        cout << "Load wallet...\n";
        pwalletMain->LoadWallet(fFirstRun);
        cout << "Register validation interface...\n";
        RegisterValidationInterface(pwalletMain);
#endif
        nScriptCheckThreads = 3;
        cout << "Create threads...\n";
        for (int i = 0; i < nScriptCheckThreads - 1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
        RegisterNodeSignals(GetNodeSignals());
    }
    ~TestingSetup() {
        cout << "Testing Setup...\n";
        threadGroup.interrupt_all();
        threadGroup.join_all();
        UnregisterNodeSignals(GetNodeSignals());
#ifdef ENABLE_WALLET
        delete pwalletMain;
        pwalletMain = NULL;
#endif
        delete pcoinsTip;
        delete pcoinsdbview;
        delete pblocktree;
#ifdef ENABLE_WALLET
        bitdb.Flush(true);
#endif
        boost::filesystem::remove_all(pathTemp);
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

void Shutdown(void *parg) {
    exit(0);
}

void StartShutdown() {
    exit(0);
}

bool ShutdownRequested() {
    return false;
}
