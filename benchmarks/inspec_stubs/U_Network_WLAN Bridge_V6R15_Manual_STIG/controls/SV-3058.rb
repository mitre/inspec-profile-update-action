control 'SV-3058' do
  title 'Unauthorized accounts must not be configured for access to the network device.'
  desc 'A malicious user attempting to gain access to the network device may compromise an account that may be unauthorized for use.  The unauthorized account may be a temporary or inactive account that is no longer needed to access the device.  Denial of Service, interception of sensitive information, or other destructive actions could potentially take place if an unauthorized account is configured to access the network device.'
  desc 'check', "Review the organization's responsibilities list and reconcile the list of authorized accounts with those accounts defined for access to the network device.

If an unauthorized account is configured for access to the device, this is a finding."
  desc 'fix', "Remove any account configured for access to the network device that is not defined in the organization's responsibilities list."
  impact 0.5
  ref 'DPMS Target WLAN Bridge'
  tag check_id: 'C-3505r5_chk'
  tag severity: 'medium'
  tag gid: 'V-3058'
  tag rid: 'SV-3058r5_rule'
  tag stig_id: 'NET0470'
  tag gtitle: 'Unauthorized accounts are configured to access device.'
  tag fix_id: 'F-3083r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
