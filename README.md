# test
Scripts for block storage functional testing
Framework:-Unittest

About the scripts:-
  1.test.py: Script for Launch Critical testcases
  2.config.py: Input Module with parameters
  3.utils.py: Module with resusable API calls
  
Initial settings:-
  1.Set the Neutron gateway for router
  2.Add security group rules to enable ping and ssh
  3.Add nova key pair and set permissions(chmod 600 file – owner can read and write)
  4.Edit the config file and provide all inputs
  
Execution:-
  1.python test.py
  2.Script has setup and teardown functions which cleans up the whole setup
  3.To be run on a fresh setup

  
  
