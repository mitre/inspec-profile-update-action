control 'SV-95143' do
  title 'The Bromium vSentry client must automatically capture and forward payloads (Malware Manifest) that were downloaded and determined to be malicious to the management console.'
  desc 'Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Forensic analysis is essential in discovering the tools, tactics, and methodologies used by the attacker, which aids in the prevention of future attacks.'
  desc 'check', 'Review base policy to ensure that the micro-virtual machine (VM) will capture the malware manifest upon the detection of malicious activity.

1. Using the management console, navigate to "Policies" and select the base policy.
2. Navigate to "Security".
3. Navigate to and inspect the "Generate isolated threat malware manifests?" policy setting.

If the Bromium vSentry client is not configured to automatically capture and forward payloads that were downloaded and determined to be malicious to the management console, this is a finding.'
  desc 'fix', 'Modify the base policy to ensure that the micro-VM will terminate the user session upon the detection of malicious activity.

1. Using the management console, navigate to "Policies" and select the base policy. 
2. Navigate to "Security".
3. Navigate to and enable the check box and radio button for the "Generate isolated threat malware manifests?" policy setting.
4. Click "Save and Deploy".'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80439'
  tag rid: 'SV-95143r1_rule'
  tag stig_id: 'BROM-00-000650'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-87245r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
