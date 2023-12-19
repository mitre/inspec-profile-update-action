control 'SV-251794' do
  title 'The NSX-T Manager must be running a release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'From the NSX-T Manager web interface, go to the System >> Upgrade.

If the NSX-T Manager current version is not the latest approved for use in DoD and supported by the vendor, this is a finding.'
  desc 'fix', 'To upgrade NSX-T, reference the upgrade guide in the documentation for the relevant version being upgraded. Refer to the NSX-T documentation and release notes for information on the latest releases.

https://docs.vmware.com/en/VMware-NSX-T-Data-Center/index.html

If NSX-T is part of a VMware Cloud Foundation, refer to that documentation for latest supported versions and upgrade guidance.'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Manager NDM'
  tag check_id: 'C-55254r810383_chk'
  tag severity: 'high'
  tag gid: 'V-251794'
  tag rid: 'SV-251794r879887_rule'
  tag stig_id: 'TNDM-3X-000097'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-55208r810384_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
