export type Lang = "en" | "hi" | "mr";

export const LANGUAGES: { code: Lang; label: string }[] = [
  { code: "en", label: "EN" },
  { code: "hi", label: "हिं" },
  { code: "mr", label: "मरा" },
];

type Translations = {
  // Login
  appTitle: string;
  appSubtitle: string;
  labelEmail: string;
  labelPassword: string;
  btnSignIn: string;
  demoHint: string;

  // Sidebar
  sidebarTitle: string;
  navThreats: string;
  navHighRisk: string;
  navUncertain: string;
  navModelLab: string;
  navCases: string;
  navMap: string;
  btnSignOut: string;

  // Hero
  heroTitleThreats: string;
  heroTitleLab: string;
  heroSubtitle: string;

  // Stats cards
  statVisible: string;
  statBlocked: string;
  statReview: string;
  statAvgRisk: string;

  // Table headers
  thTime: string;
  thFrom: string;
  thSubject: string;
  thRisk: string;
  thAuthConf: string;
  thDecision: string;

  // Detail panel
  btnRelease: string;
  btnBlock: string;
  btnUploadEml: string;
  uploadEmlHint: string;
  originTitle: string;
  originDisclaimer: string;
  btnReport: string;
  btnPreserve: string;
  btnUnlock: string;
  btnIntake: string;
  alertBanner: string;

  // Model Lab
  labHeading: string;
  labSubtitle: string;

  labTextTitle: string;
  labTextDesc: string;
  labTextPlaceholder: string;
  btnAnalyzeText: string;

  labOfficeTitle: string;
  labOfficeDesc: string;
  labOfficeUploadHint: string;

  labPdfTitle: string;
  labPdfDesc: string;
  labPdfUploadHint: string;

  labResultsPlaceholder: string;
  labScanning: string;
  labAnalyzing: string;

  // Errors / status
  errSessionExpired: string;
};

const translations: Record<Lang, Translations> = {
  en: {
    appTitle: "Guardian SOC",
    appSubtitle: "Security operations for email threats, review queues, and Model Lab.",
    labelEmail: "Email",
    labelPassword: "Password",
    btnSignIn: "Sign in",
    demoHint: "Demo: analyst@example.com / changeme1",

    sidebarTitle: "GUARDIAN SOC",
    navThreats: "Threat inbox",
    navHighRisk: "High risk",
    navUncertain: "Uncertain",
    navModelLab: "Model Lab",
    navCases: "Cases",
    navMap: "Map / campaigns",
    btnSignOut: "Sign out",

    heroTitleThreats: "Email threat center",
    heroTitleLab: "Model Lab",
    heroSubtitle: "Live Guardian decisions with SPF/DKIM/DMARC evidence and analyst actions.",

    statVisible: "Visible messages",
    statBlocked: "Blocked",
    statReview: "Needs review",
    statAvgRisk: "Avg risk",

    thTime: "Time",
    thFrom: "From",
    thSubject: "Subject",
    thRisk: "Risk",
    thAuthConf: "Auth confidence",
    thDecision: "Decision",

    btnRelease: "Release to inbox",
    btnBlock: "Block",
    btnUploadEml: "Upload .eml complaint",
    uploadEmlHint: "Same analysis engine as the SMTP gateway. Use Download original from Gmail, not Forward.",
    originTitle: "Probable originating infrastructure",
    originDisclaimer: "GeoIP is city/ASN of a mail hop — not the attacker’s house and not a live track.",
    btnReport: "Masked report",
    btnPreserve: "Preserve for FIR",
    btnUnlock: "Unlock raw (IO)",
    btnIntake: "Save complaint",
    alertBanner: "High-risk alerts",

    labHeading: "ML Model Testing",
    labSubtitle: "Test trained models individually. Models are loaded on-demand for demonstration.",

    labTextTitle: "📝 Text Phishing Detector",
    labTextDesc: "XLM-RoBERTa model (99.7% accuracy)",
    labTextPlaceholder: "Enter text to analyze for phishing patterns...",
    btnAnalyzeText: "🔍 Analyze Text",

    labOfficeTitle: "📄 Office Document Scanner",
    labOfficeDesc: "XGBoost model (99.18% ROC-AUC)",
    labOfficeUploadHint: "Upload: .doc, .docx, .xls, .xlsx, .ppt, .pptx",

    labPdfTitle: "📕 PDF Malware Scanner",
    labPdfDesc: "Random Forest model (99.91% ROC-AUC)",
    labPdfUploadHint: "Upload: .pdf files",

    labResultsPlaceholder: "Results appear here.",
    labScanning: "Scanning",
    labAnalyzing: "Analyzing...",

    errSessionExpired: "Session expired. Please sign in again.",
  },

  hi: {
    appTitle: "गार्जियन SOC",
    appSubtitle: "ईमेल खतरों, समीक्षा कतारों और मॉडल लैब के लिए सुरक्षा संचालन।",
    labelEmail: "ईमेल",
    labelPassword: "पासवर्ड",
    btnSignIn: "साइन इन करें",
    demoHint: "डेमो: analyst@example.com / changeme1",

    sidebarTitle: "गार्जियन SOC",
    navThreats: "खतरा इनबॉक्स",
    navHighRisk: "उच्च जोखिम",
    navUncertain: "अनिश्चित",
    navModelLab: "मॉडल लैब",
    navCases: "केस",
    navMap: "मानचित्र / अभियान",
    btnSignOut: "साइन आउट",

    heroTitleThreats: "ईमेल खतरा केंद्र",
    heroTitleLab: "मॉडल लैब",
    heroSubtitle: "SPF/DKIM/DMARC साक्ष्य और विश्लेषक क्रियाओं के साथ लाइव गार्जियन निर्णय।",

    statVisible: "दृश्यमान संदेश",
    statBlocked: "अवरुद्ध",
    statReview: "समीक्षा आवश्यक",
    statAvgRisk: "औसत जोखिम",

    thTime: "समय",
    thFrom: "प्रेषक",
    thSubject: "विषय",
    thRisk: "जोखिम",
    thAuthConf: "प्रमाणीकरण विश्वास",
    thDecision: "निर्णय",

    btnRelease: "इनबॉक्स में भेजें",
    btnBlock: "अवरुद्ध करें",
    btnUploadEml: "शिकायत .eml अपलोड करें",
    uploadEmlHint: "SMTP गेटवे जैसा ही विश्लेषण। Gmail से Download original उपयोग करें, Forward नहीं।",
    originTitle: "संभावित मूल अवसंरचना",
    originDisclaimer: "GeoIP मेल हॉप का शहर/ASN है — हमलावर का घर या लाइव ट्रैक नहीं।",
    btnReport: "मास्क रिपोर्ट",
    btnPreserve: "FIR के लिए सुरक्षित",
    btnUnlock: "मूल अनलॉक (IO)",
    btnIntake: "शिकायत सहेजें",
    alertBanner: "उच्च जोखिम अलर्ट",

    labHeading: "ML मॉडल परीक्षण",
    labSubtitle: "प्रशिक्षित मॉडल को व्यक्तिगत रूप से परीक्षण करें। मॉडल आवश्यकता पर लोड होते हैं।",

    labTextTitle: "📝 टेक्स्ट फ़िशिंग डिटेक्टर",
    labTextDesc: "XLM-RoBERTa मॉडल (99.7% सटीकता)",
    labTextPlaceholder: "फ़िशिंग पैटर्न के लिए विश्लेषण हेतु टेक्स्ट दर्ज करें...",
    btnAnalyzeText: "🔍 टेक्स्ट विश्लेषण करें",

    labOfficeTitle: "📄 ऑफिस दस्तावेज़ स्कैनर",
    labOfficeDesc: "XGBoost मॉडल (99.18% ROC-AUC)",
    labOfficeUploadHint: "अपलोड करें: .doc, .docx, .xls, .xlsx, .ppt, .pptx",

    labPdfTitle: "📕 PDF मालवेयर स्कैनर",
    labPdfDesc: "रैंडम फॉरेस्ट मॉडल (99.91% ROC-AUC)",
    labPdfUploadHint: "अपलोड करें: .pdf फ़ाइलें",

    labResultsPlaceholder: "परिणाम यहाँ दिखाई देंगे।",
    labScanning: "स्कैन हो रहा है",
    labAnalyzing: "विश्लेषण हो रहा है...",

    errSessionExpired: "सत्र समाप्त हो गया। कृपया फिर से साइन इन करें।",
  },

  mr: {
    appTitle: "गार्जियन SOC",
    appSubtitle: "ईमेल धोके, समीक्षा रांगा आणि मॉडेल लॅबसाठी सुरक्षा संचालन।",
    labelEmail: "ईमेल",
    labelPassword: "पासवर्ड",
    btnSignIn: "साइन इन करा",
    demoHint: "डेमो: analyst@example.com / changeme1",

    sidebarTitle: "गार्जियन SOC",
    navThreats: "धोका इनबॉक्स",
    navHighRisk: "उच्च धोका",
    navUncertain: "अनिश्चित",
    navModelLab: "मॉडेल लॅब",
    navCases: "केस",
    navMap: "नकाशा / मोहीम",
    btnSignOut: "साइन आउट करा",

    heroTitleThreats: "ईमेल धोका केंद्र",
    heroTitleLab: "मॉडेल लॅब",
    heroSubtitle: "SPF/DKIM/DMARC पुरावे आणि विश्लेषक क्रियांसह थेट गार्जियन निर्णय।",

    statVisible: "दृश्यमान संदेश",
    statBlocked: "अवरोधित",
    statReview: "समीक्षा आवश्यक",
    statAvgRisk: "सरासरी धोका",

    thTime: "वेळ",
    thFrom: "प्रेषक",
    thSubject: "विषय",
    thRisk: "धोका",
    thAuthConf: "प्रमाणीकरण विश्वास",
    thDecision: "निर्णय",

    btnRelease: "इनबॉक्समध्ये सोडा",
    btnBlock: "अवरोधित करा",
    btnUploadEml: "तक्रार .eml अपलोड करा",
    uploadEmlHint: "SMTP गेटवे सारखेच विश्लेषण. Gmail मधून Download original वापरा, Forward नाही.",
    originTitle: "संभाव्य मूळ पायाभूत सुविधा",
    originDisclaimer: "GeoIP मेल हॉपचे शहर/ASN आहे — हल्लेखोराचे घर किंवा थेट ट्रॅक नाही.",
    btnReport: "मास्क रिपोर्ट",
    btnPreserve: "FIR साठी जतन",
    btnUnlock: "मूळ अनलॉक (IO)",
    btnIntake: "तक्रार जतन करा",
    alertBanner: "उच्च धोका अलर्ट",

    labHeading: "ML मॉडेल चाचणी",
    labSubtitle: "प्रशिक्षित मॉडेल स्वतंत्रपणे तपासा. मॉडेल मागणीनुसार लोड होतात.",

    labTextTitle: "📝 टेक्स्ट फिशिंग डिटेक्टर",
    labTextDesc: "XLM-RoBERTa मॉडेल (99.7% अचूकता)",
    labTextPlaceholder: "फिशिंग नमुन्यांसाठी विश्लेषण करण्यासाठी मजकूर प्रविष्ट करा...",
    btnAnalyzeText: "🔍 मजकूर विश्लेषण करा",

    labOfficeTitle: "📄 ऑफिस दस्तऐवज स्कॅनर",
    labOfficeDesc: "XGBoost मॉडेल (99.18% ROC-AUC)",
    labOfficeUploadHint: "अपलोड करा: .doc, .docx, .xls, .xlsx, .ppt, .pptx",

    labPdfTitle: "📕 PDF मालवेअर स्कॅनर",
    labPdfDesc: "रँडम फॉरेस्ट मॉडेल (99.91% ROC-AUC)",
    labPdfUploadHint: "अपलोड करा: .pdf फाइल्स",

    labResultsPlaceholder: "निकाल येथे दिसतील.",
    labScanning: "स्कॅन होत आहे",
    labAnalyzing: "विश्लेषण होत आहे...",

    errSessionExpired: "सत्र संपले. कृपया पुन्हा साइन इन करा.",
  },
};

export function getTranslations(lang: Lang): Translations {
  return translations[lang];
}
