control 'SV-257516' do
  title 'OpenShift must display the Standard Mandatory DOD Notice and Consent Banner before granting access to platform components.'
  desc 'OpenShift has countless components where different access levels are needed. To control access, the user must first log into the component and then be presented with a DOD-approved use notification banner before granting access to the component. This guarantees privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc 'check', 'To verify the OpenShift CLI tool is configured to display the DOD Notice and Consent Banner, do either of the following steps:

Log in to OpenShift using the oc CLI tool.

oc login -u <USER> <OPENSHIFT_URL>
enter password when prompted

If the DOD Notice and Consent Banner is not displayed, this is a finding.

Or

Verify that motd config map exists and contains the DOD Notice and Consent Banner by executing the following:

oc describe configmap/motd -n openshift

If the configmap does not exist, or it does not contain the DOD Notice and Consent Banner text in the message data attribute, this is a finding.'
  desc 'fix', %q(The following command will create a configmap that displays the DOD Notice and Consent Banner when logging in using the OpenShift CLI tool by executing the following:

echo 'apiVersion: v1
kind: ConfigMap
metadata:
  name: motd
  namespace: openshift
data:
  message: "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."' | oc apply -f -)
  impact 0.3
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61251r921489_chk'
  tag severity: 'low'
  tag gid: 'V-257516'
  tag rid: 'SV-257516r921491_rule'
  tag stig_id: 'CNTR-OS-000130'
  tag gtitle: 'SRG-APP-000068-CTR-000120'
  tag fix_id: 'F-61175r921490_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
