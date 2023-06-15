from chalice import Chalice
from chalicelib.api.securityhub import securityhub
from chalicelib.events.findings import sechub_findings
from chalicelib.lambda_function.onboard import onboard
from chalicelib.lambda_function.offboard import offboard
from chalicelib.lambda_function.enable_standards import enable_standards
from chalicelib.lambda_function.disable_standards import disable_standards
from chalicelib.lambda_function.guardduty_onboard import guardduty_onboard
from chalicelib.lambda_function.guardduty_offboard import guardduty_offboard
from chalicelib.lambda_function.iamanalyzer_onboard import iamanalyzer_onboard
from chalicelib.lambda_function.findings_handler.findings_handler import findings_handler


app = Chalice(app_name='securityhub')

app.register_blueprint(securityhub)
app.register_blueprint(onboard)
app.register_blueprint(offboard)
app.register_blueprint(enable_standards)
app.register_blueprint(disable_standards)
app.register_blueprint(guardduty_onboard)
app.register_blueprint(guardduty_offboard)
app.register_blueprint(iamanalyzer_onboard)
app.register_blueprint(sechub_findings)
app.register_blueprint(findings_handler)








