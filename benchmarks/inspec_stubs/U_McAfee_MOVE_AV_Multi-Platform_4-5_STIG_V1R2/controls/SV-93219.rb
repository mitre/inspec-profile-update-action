control 'SV-93219' do
  title 'The McAfee MOVE AV Common Options policy must be configured to not rotate log files until they reach at least 10 MB in size.'
  desc 'Forensic identification is the practice of identifying infected hosts by looking for evidence of recent infections. The evidence may be very recent (only a few minutes old) or not so recent (hours or days old); the older the information is, the less accurate it is likely to be. The most obvious sources of evidence are those that are designed to identify malware activity, such as anti-virus software, content filtering (e.g., anti-spam measures), IPS, and SIEM technologies. The logs of security applications might contain detailed records of suspicious activity and might also indicate whether a security compromise occurred or was prevented.

While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. To avoid the risk of logs growing to the size of impacting the operating system, the log size and number of log files will be restricted but must be large enough to retain forensic value.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus Common 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Click "Show Advanced".

Under "Logging", verify the "Rotate log file content when the file size reaches" field is set to "10" MB or greater.

If the "Rotate log file content when the file size reaches" field is not set to "10" MB or greater, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus Common 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Click "Show Advanced".

Under "Logging", set the "Rotate log file content when the file size reaches" value to "10" MB or greater.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78075r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78513'
  tag rid: 'SV-93219r1_rule'
  tag stig_id: 'MV45-COP-000003'
  tag gtitle: 'MV45-COP-000003'
  tag fix_id: 'F-85247r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001489']
  tag nist: ['AU-3 (2)']
end
