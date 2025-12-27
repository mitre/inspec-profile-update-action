control 'SV-7028' do
  title 'Auditing of user access and fax logs must be enabled when fax from the network is enabled.'
  desc 'Without auditing the originator and destination of a fax cannot be determined. Prosecuting of an individual who maliciously compromises sensitive data via a fax will be hindered without audits.

The SA will ensure auditing of user access and fax logging is enabled if fax from the network is enabled.'
  desc 'check', 'The reviewer will, with the assistance from the SA, verify auditing of user access and fax logging is enabled if fax from the network is enabled. If auditing of user access and fax logging is not enabled, this is a finding.'
  desc 'fix', 'Configure the MFD to audit faxing. If this is not possible, disable the fax functionality and disconnect the phone line from the MFD.'
  impact 0.3
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3018r2_chk'
  tag severity: 'low'
  tag gid: 'V-6803'
  tag rid: 'SV-7028r2_rule'
  tag stig_id: 'MFD07.004'
  tag gtitle: 'MFD fax from network auditing'
  tag fix_id: 'F-6477r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
