control 'SV-218766' do
  title 'The IIS 10.0 websites must use ports, protocols, and services according to Ports, Protocols, and Services Management (PPSM) guidelines.'
  desc 'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The web server must provide the capability to disable or deactivate network-related services deemed to be non-essential to the server mission, too unsecure, or prohibited by the PPSM CAL and vulnerability assessments.

Failure to comply with DoD ports, protocols, and services (PPS) requirements can result in compromise of enclave boundary protections and/or functionality of the AIS.

The ISSM will ensure web servers are configured to use only authorized PPS in accordance with the Network Infrastructure STIG, DoD Instruction 8551.1, PPSM, and the associated PPS Assurance Category Assignments List.'
  desc 'check', 'Review the website to determine if HTTP and HTTPs (e.g., 80 and 443) are used in accordance with those ports and services registered and approved for use by the DoD PPSM. Any variation in PPS will be documented, registered, and approved by the PPSM.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

In the "Action" Pane, click "Bindings".

Review the ports and protocols. If unknown ports or protocols are used, then this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

In the "Action" Pane, click "Bindings".

Edit to change an existing binding and set the correct ports and protocol.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20239r311196_chk'
  tag severity: 'medium'
  tag gid: 'V-218766'
  tag rid: 'SV-218766r850589_rule'
  tag stig_id: 'IIST-SI-000239'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-20237r311197_fix'
  tag 'documentable'
  tag legacy: ['SV-109357', 'V-100253']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
