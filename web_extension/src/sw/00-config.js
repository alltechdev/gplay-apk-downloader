// 00-config.js — constants shared across the SW modules.
// Loaded first via importScripts so every later module sees these globals.

const PAGE_URL = chrome.runtime.getURL('index.html');
const DISPENSER_URL = 'https://auroraoss.com/api/auth';
const PLAY_BASE = 'https://android.clients.google.com/fdfe';
const SEARCH_URL = 'https://play.google.com/store/search';

const AUTH_STORAGE_KEY = 'gplaydl.auth';
const ARCH_STORAGE_KEY = 'gplaydl.arch';
const DOWNLOAD_RULE_MAP_KEY = 'gplaydl.downloadRules';

const AUTH_TTL_MS = 1000 * 60 * 60 * 4;
const DEFAULT_ARCH = 'arm64-v8a';

const DNR_DISPENSER_ID = 1;
const DNR_FDFE_ID = 2;
const DNR_CDN_ID = 3;
const DNR_SEARCH_ID = 4;
const DNR_DOWNLOAD_ID_MIN = 100;
const DNR_DOWNLOAD_ID_MAX = 9999;

const PLAY_FALLBACK_UA = 'Android-Finsky/45.8.21-31 [0] [PR] 747433787 (api=3,versionCode=84582130,sdk=35,device=tegu,hardware=tegu,product=tegu,platformVersionRelease=15,model=Pixel%209a,buildId=BD4A.250405.003,isWideScreen=0,supportedAbis=arm64-v8a)';
const DISPENSER_UA = 'com.aurora.store-4.6.1-70';
// Plain desktop-Chrome UA for `play.google.com/store/*` HTML scrapes. Without
// a "real" UA the Play Store redirects to accounts.google.com sign-in.
const PLAY_WEB_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const DFE_ENCODED_TARGETS = 'CAESN/qigQYC2AMBFfUbyA7SM5Ij/CvfBoIDgxXrBPsDlQUdMfOLAfoFrwEHgAcBrQYhoA0cGt4MKK0Y2gI';
const DFE_PHENOTYPE = 'H4sIAAAAAAAAAB3OO3KjMAAA0KRNuWXukBkBQkAJ2MhgAZb5u2GCwQZbCH_EJ77QHmgvtDtbv-Z9_H63zXXU0NVPB1odlyGy7751Q3CitlPDvFd8lxhz3tpNmz7P92CFw73zdHU2Ie0Ad2kmR8lxhiErTFLt3RPGfJQHSDy7Clw10bg8kqf2owLokN4SecJTLoSwBnzQSd652_MOf2d1vKBNVedzg4ciPoLz2mQ8efGAgYeLou-l-PXn_7Sna1MfhHuySxt-4esulEDp8Sbq54CPPKjpANW-lkU2IZ0F92LBI-ukCKSptqeq1eXU96LD9nZfhKHdtjSWwJqUm_2r6pMHOxk01saVanmNopjX3YxQafC4iC6T55aRbC8nTI98AF_kItIQAJb5EQxnKTO7TZDWnr01HVPxelb9A2OWX6poidMWl16K54kcu_jhXw-JSBQkVcD_fPsLSZu6joIBAAA';
