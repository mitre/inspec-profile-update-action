control 'SV-7019' do
  title 'A MFD or printer is not configured to restrict jobs to those from print spoolers.'
  desc 'If MFDs or printers are not restricted to accept print jobs only from print spoolers that authenticate the user and log the job, a denial of service can be created by the MFD or printer accepting one or more large print jobs from an unauthorized user.

The SA will ensure MFDs and printers are configured to restrict jobs only to print spoolers, not directly from users.

Mobile device print jobs must be sent to a print spooler, they must not be sent directly from a mobile device to a MFD or printer that supports direct wireless printing (e.g., AirPrint, Wi-Fi Direct, etc.).

The configuration is accomplished by restricting access, by IP, to those of the print spooler and SAs.  If supported, IP restriction is accomplished on the device, or if not supported, by placing the device behind a firewall, switch or router with an appropriate discretionary access control list.'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that MFDs and printers are configured to restrict jobs only to print spoolers, not directly from users.

If print jobs are sent directly to the MFD or printer, this is a finding.

If direct wireless printing (e.g., AirPrint, Wi-Fi Direct, etc.), is enabled on the MFD or printer, this is a finding.'
  desc 'fix', 'Reconfigure the device to restrict access, by IP, to those of the print spoolers and SAs.  If the device does not support this functionality, place the device behind a firewall, switch or router with an appropriate discretionary access control list. Disable direct wireless printing on the MFD or printer.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2998r4_chk'
  tag severity: 'medium'
  tag gid: 'V-6794'
  tag rid: 'SV-7019r3_rule'
  tag stig_id: 'MFD04.001'
  tag gtitle: 'MFD/Printer Restrict Jobs Only From Print Spooler'
  tag fix_id: 'F-6461r2_fix'
  tag 'documentable'
  tag potential_impacts: 'Client systems that are configured to bypass the print server that spools print jobs will lose access to the printer until reconfigured.'
end
