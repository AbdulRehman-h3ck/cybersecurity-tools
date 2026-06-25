import json
import g4f
import nest_asyncio

# GUI ke background threads ko smoothly chalane ke liye
nest_asyncio.apply()

class AIReportSummarizer:
    def __init__(self):
        # 🔥 PLAN B: BINA KISI API KEY KE CHALEGA 🔥
        pass
        
    def generate_summary(self, report_dict):
        try:
            # AI ke liye prompt ready karein
            prompt = f"""
            You are an expert Cybersecurity CISO & SOC Analyst. I will provide you with a raw JSON report of an Android APK threat analysis.
            Your job is to write a concise, professional, 4-5 sentence "Executive Summary" of the risks. 
            Focus on:
            1. The final verdict and score.
            2. Any critical malicious behaviors.
            3. Network threats (Hardcoded IPs, Tunneling, C2).
            4. Potential impact on the end-user.
            
            Keep the tone urgent but professional. Do NOT use markdown bold/italics, just provide a clean plain text paragraph.
            
            Raw Report Data:
            {json.dumps(report_dict, default=str)}
            """
            
            # g4f automatically available free providers message bhejay ga
            response = g4f.ChatCompletion.create(
                model="gpt-4", # Hum GPT-4 ka free version try kar rahe hain
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Agar response string ki form mein aaye
            if isinstance(response, str):
                return response.strip()
            else:
                return str(response).strip()
                
        except Exception as e:
            return f"⚠️ Plan B AI Error: Free Providers are currently busy or blocking the request. ({str(e)})"
