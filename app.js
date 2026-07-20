// إعدادات الاتصال بخادم PythonAnywhere الخاص بك
const API_BASE_URL = 'https://cybersecuritypro.pythonanywhere.com';

// تخزين الأداة الحالية المحددة
let selectedTool = 'url';
const inputField = document.getElementById('inputData');
const label = document.getElementById('input-label');
const resultContainer = document.getElementById('result-container');
const output = document.getElementById('output');
const scanBtn = document.getElementById('scanBtn');
const loadingDiv = document.getElementById('loading');

// وظيفة تغيير التسمية والنمط عند الضغط على الأدوات
document.querySelectorAll('.tool-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        // إزالة التفعيل من الجميع
        document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
        // تفعيل الزر الحالي
        this.classList.add('active');
        
        selectedTool = this.getAttribute('data-tool');
        
        // تغيير النص والـ Placeholder حسب الأداة
        const placeholders = {
            'url': 'مثال: https://cybershield.pro أو أي رابط',
            'email': 'مثال: user@example.com',
            'phone': 'مثال: +967773749784 (بدون مسافات)',
            'password': 'أدخل كلمة المرور لاختبار قوتها',
            'domain': 'مثال: cybershield.com',
            'ip': 'مثال: 8.8.8.8',
            'hash': 'أدخل الهاش (MD5, SHA256, إلخ)',
            'jwt': 'أدخل توكن JWT الخاص بك',
            'apikey': 'أدخل مفتاح API للتحقق منه'
        };
        label.textContent = `أدخل ${this.textContent.trim()} هنا...`;
        inputField.placeholder = placeholders[selectedTool] || 'أدخل البيانات للفحص...';
        inputField.value = '';
        
        // إخفاء النتيجة السابقة
        resultContainer.style.display = 'none';
    });
});

// الدالة الرئيسية لإجراء الفحص
async function runScan() {
    const data = inputField.value.trim();
    if (!data) {
        alert('الرجاء إدخال البيانات للفحص!');
        return;
    }

    // تجهيز واجهة المستخدم للفحص
    scanBtn.disabled = true;
    loadingDiv.style.display = 'block';
    resultContainer.style.display = 'none';

    try {
        // إرسال الطلب إلى API الخلفية
        const response = await fetch(`${API_BASE_URL}/api/v1/scan/${selectedTool}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                [selectedTool]: data
            })
        });

        // قراءة النتيجة
        const jsonResult = await response.json();

        // عرض النتيجة بشكل جميل
        loadingDiv.style.display = 'none';
        resultContainer.style.display = 'block';
        
        // تنسيق JSON لعرضه
        output.textContent = JSON.stringify(jsonResult, null, 2);

    } catch (error) {
        loadingDiv.style.display = 'none';
        resultContainer.style.display = 'block';
        output.textContent = '❌ خطأ في الاتصال بالسيرفر: ' + error.message;
        output.style.color = '#f87171'; // أحمر فاتح
    } finally {
        scanBtn.disabled = false;
        setTimeout(() => { output.style.color = '#a5f3fc'; }, 3000); // إعادة اللون الطبيعي
    }
}