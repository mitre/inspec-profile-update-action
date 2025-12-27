control 'SV-80435' do
  title 'Trend Deep Security must be configured to perform real-time malicious code protection scans of files from external sources at endpoints as the files are downloaded, opened, or executed in accordance with organizational security policy.'
  desc 'Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Malicious code includes viruses, worms, Trojan horses, and Spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'Review the Trend Deep Security server to ensure real-time malicious code protection scans are performed on files from external sources at endpoints as the files are downloaded, opened, or executed in accordance with organizational security policy.

Verify the Anti-Malware, Real-Time Scan is enabled by reviewing the following settings under the “Policies” tab.  Under “Policies” right click and select “Details” and choose “Anti-Malware.

Review the following settings: Anti-Malware State is set to “On” and the “Real-Time Scan” is set to “Default.”

If the two settings are not configured accordingly, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to perform real-time malicious code protection scans of files from external sources at endpoints as the files are downloaded, opened, or executed in accordance with organizational security policy.

To enable malicious code protection via the anti-malware, configure the following settings under the “Policies” tab.
Under “Policies” right clicking and selecting “Details.” Configure the following settings:

1. Under the Overview >> General tab, set "Anti-Malware" to “On”
2. Under the Anti-Malware >> General tab, set “Real-Time Scan” to “Default”. Click “OK” when finished.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66593r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65945'
  tag rid: 'SV-80435r1_rule'
  tag stig_id: 'TMDS-00-000215'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-72021r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
