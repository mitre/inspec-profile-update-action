control 'SV-230953' do
  title 'Forescout must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.

In Oct 2021, there is plan to make Version 7 end-of-life. This will be stated on the product lifecycle page of the Forescout website.  All versions of V8 and above are authorized for use in DoD.

Version 8 or later is mandatory after October 2021.'
  desc 'check', 'Check that Forescout is still running supported operating system versions and that all vulnerability patches and updates have been applied.

Verify the installed version is supported by Forescout by checking the Forescout support website lifecycle page. Currently, Version 8 or later is mandatory after October 2021.

If Forescout is running an operating system release that is not supported by the vendor, this is a finding.'
  desc 'fix', 'Check that Forescout is still running supported operating system versions and that all vulnerability patches and updates have been applied.

Establish and document a procedure that requires the auditing of OS versions and any patches and updates have been applied in accordance with Forescout support website lifecycle page.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33883r603698_chk'
  tag severity: 'medium'
  tag gid: 'V-230953'
  tag rid: 'SV-230953r615886_rule'
  tag stig_id: 'FORE-NM-000260'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-33856r603699_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
