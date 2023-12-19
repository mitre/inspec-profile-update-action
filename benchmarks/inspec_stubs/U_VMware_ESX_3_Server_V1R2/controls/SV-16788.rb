control 'SV-16788' do
  title 'ESX Server updates are not tested.'
  desc 'Organizations need to stay current with all applicable ESX Server software updates that are released from VMware. In order to be aware of updates as they are released, virtualization server administrators will subscribe to ESX Server vendor security notices, updates, and patches to ensure that all new vulnerabilities are known. New ESX Server patches and updates should be reviewed for the ESX Server before moving them into a production environment. ESX Server patches will be tested first in a development environment and any issues or special precautions will be documented, as a patch could technically disable all virtual networks and machines.'
  desc 'check', 'Ask the IAO/SA to show you where the test and development ESX Server is located.  At the service console of the test and development ESX Server perform the following command:
# esxupdate –l query

The output will look similar to the following:

Installed software bundles
-----Name----        --Install Date--   --------Summary--------
3.5.0-56329          23:37:26 11/04/08  Full installation of ESX 3.5.0-56329

ESX350-200802055-BG  23:49:26 11/04/08  Fix COS running Dell OM5 w/QLogic

ESX350-200803066-SG  23:50:02 11/04/08  Fix COS security bug

If no patch results are returned, this is a finding.  

The test and development ESX Server cannot be the production ESX Server(s).'
  desc 'fix', 'Use the test and development ESX Server to test all patches before moving them to production.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15847'
  tag rid: 'SV-16788r1_rule'
  tag stig_id: 'ESX0480'
  tag gtitle: 'ESX Server updates are not tested.'
  tag fix_id: 'F-15801r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
