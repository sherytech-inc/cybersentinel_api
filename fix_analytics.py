import re

path = 'app/services/reporting/analytics_service.py'
with open(path, 'r') as f:
    content = f.read()

# Make sure we import get_settings at the top if not present
if 'from app.core.config import get_settings' not in content:
    content = content.replace('from supabase import AsyncClient', 'from supabase import AsyncClient\nfrom app.core.config import get_settings')

# Replace `if db_has_demo_columns():` with `if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE:`
content = re.sub(r'if db_has_demo_columns\(\):', 'if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE:', content)

with open(path, 'w') as f:
    f.write(content)
