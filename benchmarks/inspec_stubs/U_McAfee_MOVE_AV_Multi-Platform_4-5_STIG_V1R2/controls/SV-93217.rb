control 'SV-93217' do
  title 'The McAfee MOVE AV Common Options policy must be configured to send all events to the HBSS ePO server.'
  desc 'Forensic identification is the practice of identifying infected hosts by looking for evidence of recent infections. The evidence may be very recent (only a few minutes old) or not so recent (hours or days old); the older the information is, the less accurate it is likely to be. The most obvious sources of evidence are those that are designed to identify malware activity, such as anti-virus software, content filtering (e.g., anti-spam measures), IPS, and SIEM technologies. The logs of security applications might contain detailed records of suspicious activity and might also indicate whether a security compromise occurred or was prevented.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus Common 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Click "Show Advanced".

Under "Events", verify the "Send events to McAfee ePO" check box is selected.

If the "Send events to McAfee ePO" check box is not selected, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus Common 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Click "Show Advanced".

Under "Events", select the "Send events to McAfee ePO" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78073r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78511'
  tag rid: 'SV-93217r1_rule'
  tag stig_id: 'MV45-COP-000002'
  tag gtitle: 'MV45-COP-000002'
  tag fix_id: 'F-85245r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001489']
  tag nist: ['AU-3 (2)']
end
