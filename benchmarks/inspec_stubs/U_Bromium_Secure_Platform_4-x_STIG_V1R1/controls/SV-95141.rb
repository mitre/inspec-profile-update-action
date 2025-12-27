control 'SV-95141' do
  title 'The Bromium vSentry client must automatically terminate a micro-virtual machine (VM) when any malicious activities are detected within the micro-VM.'
  desc "Execution of malicious code represents an immediate threat to the security posture of the endpoint. Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

The DoD has selected automatic termination as the default response. However, this does not fully leverage Bromium's ability to capture near-real-time forensic data as an attack occurs. Note that the malicious code is in a micro-VM, thus it cannot impact the endpoint processes outside of the VM. 

Note: Letting a known harmful program run is restricted to testing platforms, for forensics collection, or when justified by mission needs. STIG provides guidance to prevent the vClients from running known malicious applications or closing the micro-VM with malicious code is detected."
  desc 'check', 'Review documentation for test system or mission need that justifies an exception to this setting in order to collect forensics about the malicious code. If this documentation exists, this is not a finding.

Review base policy to ensure that the micro-VM will terminate the user session upon the detection of malicious activity.

1. Using the management console, navigate to "Policies" and select the base policy.
2. Navigate to "Security".
3. Navigate to and inspect the "Alert user on a threat event?" policy setting.

Check  every applicable Delta Policy using the same procedure to verify that the Base Policy has not been superseded.

If the Bromium vSentry client is not configured to automatically terminate a micro-VM when any malicious activities are detected within the micro-VM, this is a finding.'
  desc 'fix', 'Review base policy to ensure that the micro-VM will terminate the user session upon the detection of malicious activity. Document test system or mission needs that justifies an exception to this setting in order to collect forensics about the malicious code. Also document circumstances under this function that can temporarily be used to collect forensics information.

1. Using the management console, navigate to "Policies" and select the Base Policy.
2. Navigate to "Security".
3. Navigate to the "Alert user on a threat event?" policy setting.
4. Choose the "Stop operation and alert user" setting.
5. Click "Save and Deploy".

Note: Do not supersede this policy in any Delta Policy.'
  impact 0.7
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80109r1_chk'
  tag severity: 'high'
  tag gid: 'V-80437'
  tag rid: 'SV-95141r1_rule'
  tag stig_id: 'BROM-00-000645'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-87243r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
