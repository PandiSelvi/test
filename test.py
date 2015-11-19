import random
import utils
import time
import os
import unittest
import traceback
import logging
import paramiko
import select
import shlex
import config
LOG = logging


def main():
    try:
        errors, failures = main_section()
        test_summary(errors, failures)
    except SystemExit:
        pass  # do nothing, just exit
    except:
        LOG.error("Unexpected error:")
        LOG.error(traceback.format_exc())


def test_summary(errors, failures):
    error_count = len(errors)
    failure_count = len(failures)
    if (error_count > 0 or failure_count > 0):
        LOG.info("************************************************************")
        LOG.info("            TEST COMPLETED WITH FAILURES")
        LOG.info("************************************************************")
    else:
        LOG.info("test completed and exiting normally")
        LOG.info("************************************************************")
        LOG.info("            TEST COMPLETED - ALL TESTS PASSED")
        LOG.info("************************************************************")


def main_section():
    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='/home/ubuntu/test.log',
                    filemode='w')

    class Functional_tests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.tenant_id, cls.auth_token = utils.keystone_login(config.tenant_name,
                                                                 config.user_name, config.password)
            instances = utils.instance_list(cls.tenant_id, cls.auth_token)
            if len(instances["servers"]) > 0:
                for instance in range(len(instances["servers"])):
                    instance_id = instances["servers"][instance]["id"]
                    value = utils.instance_delete(cls.tenant_id, cls.auth_token, instance_id)
                    assert value != True, "Instance not deleted"
            floating_ips = utils.floating_ip_list(cls.tenant_id, cls.auth_token)
            if len(floating_ips["floatingips"]) > 0:
                for ip in range(len(floating_ips["floatingips"])):
                    ip_id = floating_ips["floatingips"][ip]["id"]
                    value = utils.floating_ip_delete(cls.tenant_id, cls.auth_token, ip_id)
                    assert value != True, "IP not deleted"
            volumes = utils.volume_list(cls.tenant_id, cls.auth_token)
            if len(volumes["volumes"]) > 0:
                for volume in range(len(volumes["volumes"])):
                    volume_id = volumes["volumes"][volume]["id"]
                    value = utils.volume_delete(
                    cls.tenant_id, cls.auth_token, volume_id)
                    assert value != True, "Volume not deleted"
            backups = utils.backup_list(cls.tenant_id, cls.auth_token)
            if len(backups["backups"]) > 0:
               for backup in range(len(backups["backups"])):
                   backup_id = backups["backups"][backup]["id"]
                   value = utils.backup_delete(
                   cls.tenant_id, cls.auth_token, backup_id)
                   assert value != True, "Backup not deleted"


        def setUp(self):
            self.tenant_id, self.auth_token = utils.keystone_login(config.tenant_name, config.user_name, config.password)


        def create_non_bootable_volume(self, name, size):
            """ Creates non bootable volume
                Return value : volume_id """
            content = utils.volume_create(self.tenant_id,
                                          self.auth_token, name, size)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id,
                                                     self.auth_token, volume_id)
            self.assertEquals(True, is_available,
                              "volume is not in available state")
            return volume_id


        def create_bootable_volume(self, name, size, image_name):
            """ Creates bootable volume
             Return value : volume_id """
            image_id = utils.image_id(self.tenant_id, self.auth_token, image_name)
            content = utils.volume_create(self.tenant_id,
                                          self.auth_token, name, size, image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id,
                                                     self.auth_token, volume_id)
            self.assertEquals(True, is_available,
                              "volume is not in available state")
            return volume_id


        def create_instance(self, image_name, flavor, key_name, network, security_group, instance_name):
            """ Create an instance
                Return value : instance_id """
            image_id = utils.image_id(self.tenant_id,
                                      self.auth_token, image_name)
            content = utils.instance_create(self.tenant_id, self.auth_token,
                                            instance_name, image_id, flavor, key_name, network, security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active)
            return instance_id


        def attach_volume(self, instance_id, volume_id):
            """ Attaches volume to an instance
                Return value : device """
            content = utils.volume_attach(self.tenant_id, self.auth_token, instance_id, volume_id)
            self.assertEquals(instance_id, content["volumeAttachment"]["serverId"])
            self.assertEquals(volume_id, content["volumeAttachment"]["volumeId"])
            details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            while details["volume"]["status"] == "attaching":
                time.sleep(5)
                details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals("in-use", details["volume"]["status"], "Volume is not in 'in-use' state")
            for instance in range(len(details["volume"]["attachments"])):
                if details["volume"]["attachments"][instance]["server_id"] == instance_id:
                    device = details["volume"]["attachments"][instance]["device"]
                    return device


        def detach_volume(self, instance_id, volume_id):
            """ Detaches volume
                Return value : None """
            content = utils.volume_detach(self.tenant_id, self.auth_token, instance_id, volume_id)
            content = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            while content["volume"]["status"] == "detaching":
                time.sleep(5)
                content = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals("available",content["volume"]["status"])


        def create_backup(self,volume_id, backup_name):
            """ Creates a backup
            Return value : backup_id """
            content = utils.backup_create(self.tenant_id, self.auth_token, volume_id, backup_name)
            backup_id = content["backup"]["id"]
            time.sleep(10)
            is_available = utils.is_backup_available(self.tenant_id, self.auth_token, backup_id)
            self.assertEquals(True, is_available, "backup creation failed")
            backup_details = utils.backup_details(self.tenant_id, self.auth_token, backup_id)
            self.assertEquals(volume_id,backup_details["backup"]["volume_id"])
            return backup_id


        def restore_backup(self,backup_id):
            """ Restores  backup
                Return value : volume_id """
            content = utils.backup_restore(self.tenant_id, self.auth_token, backup_id)
            volume_id = content["restore"]["volume_id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True, is_available, "restore failed")
            return volume_id


        def test_01(self):
            """ Create non-bootable volume """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name,
                                                        config.non_bootable_volume_size)
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True , is_available, "Volume is not in available state")
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(config.non_bootable_volume_size,
                              volume_details["volume"]["size"],"Volume size is different than the requested size")


        def test_02(self):
            """ Create maximum number of non bootable volumes """
            for volume in range(config.volume_limit):
                volume_name = "non_boot"+str(volume)
                volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name,
                                                            config.non_bootable_volume_size)
                is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
                self.assertEquals(True , is_available, "Volume is not in available state")
                volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
                self.assertEquals(config.non_bootable_volume_size,
                                  volume_details["volume"]["size"], "Volume size is different than the requested size")
                volume_list = utils.volume_list(self.tenant_id, self.auth_token)
            self.assertEquals(config.volume_limit, len(volume_list["volumes"]),
                              "Number of volumes doesnot meet the maximum limit")


        def test_03(self):
            """ Create bootable volume """
            volume_id = self.create_bootable_volume(config.bootable_volume_name,
                                                    config.bootable_volume_size, config.image_name)
            volume_details = utils.volume_details(self.tenant_id, self.auth_token,volume_id)
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True , is_available, "Volume is not in available state")
            self.assertEquals(config.bootable_volume_size,
                              volume_details["volume"]["size"], "volume size is different than the requested size")
            self.assertEquals("true", volume_details["volume"]["bootable"], "volume is non-bootable")


        def test_04(self):
            """ Create bootable volume while creating instance """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create_while_creating_instance(self.tenant_id, self.auth_token, image_id,
                                                                config.bootable_volume_size, config.key_name,
                                                                config.instance_name, config.flavor, config.network,
                                                                config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active)
            instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            volume_id = instance_details["server"]["os-extended-volumes:volumes_attached"][0]["id"]
            volume_details = utils.volume_details(self.tenant_id, self.auth_token,volume_id)
            self.assertEquals(instance_id,volume_details["volume"]["attachments"][0]["server_id"],"notequal")


        def test_05(self):
            """ Create muliple boot volumes """
            for volume in range(3):
                volume_name = config.bootable_volume_name+str(volume)
                volume_id = self.create_bootable_volume(config.bootable_volume_name,
                                                      config.bootable_volume_size, config.image_name)
                is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
                self.assertEquals(True , is_available, "%s is not in available state" % volume_name)
                volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
                self.assertEquals(config.bootable_volume_size,volume_details["volume"]["size"],
                                  " %s size is different than the requested size" % volume_name)
                self.assertEquals("true",volume_details["volume"]["bootable"],
                                  "%s is non-bootable" % volume_name)
                volume_list = utils.volume_list(self.tenant_id, self.auth_token)
            self.assertEquals(3,len(volume_list["volumes"]))


        def test_06(self):
            """ Create multiple bootable and non_bootable volumes """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            my_list = [utils.volume_create(tenant_id=self.tenant_id, auth_token=self.auth_token,
                                           name="", size=config.non_bootable_volume_size, image_id=""),
                       utils.volume_create(self.tenant_id, self.auth_token,
                                           config.bootable_volume_name, config.bootable_volume_size, image_id)]
            func = utils.random_pick(my_list)
            for i in range(4):
                volume = (next(func))
                volume_id = volume["volume"]["id"]
                is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
                volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
                self.assertEquals("available", volume_details["volume"]["status"],"volume is not in available state")


        def test_07(self):
            """  Negative-Create volumes greater than maximum limit """
            for volume in range(1,config.volume_limit):
                volume_name = config.non_bootable_volume_name+str(volume)
                try:
                    volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name,
                                                              config.non_bootable_volume_size)
                except Exception as e:
                    self.assertIn("VolumeLimitExceeded", str(e), "Exception not found")


        def test_08(self):
            """ Attach volume while creating instance """
            content = utils.volume_create(self.tenant_id, self.auth_token, config.non_bootable_volume_name,
                                        config.non_bootable_volume_size)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True, is_available)
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_attach_while_creating_instance(self.tenant_id, self.auth_token, image_id,
                                                                volume_id, config.key_name, config.instance_name, config.flavor,                                                                   config.network,config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active)
            instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id, volume_details["volume"]["attachments"][0]["server_id"],
                              "Server id not found in volume details")


        def test_09(self):
            """ Attach non bootable volume """
            instance_id = self.create_instance(config.image_name, config.flavor,
                                               config.key_name,config.network, config.security_group, config.instance_name)
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name,
                                                        config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)


        def test_10(self):
            """ Attach multiple non bootable volume """
            instance_id = self.create_instance(config.image_name, config.flavor,
                                               config.key_name, config.network, config.security_group, config.instance_name)
            for i in range(3):
                volume_name = config.non_bootable_volume_name+str(i)
                volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
                device = self.attach_volume(instance_id, volume_id)


        def test_11(self):
            """ Attach_non_bootable_when_vm is shut off """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name, config.network, config.security_group, config.instance_name)   
            content = utils.nova_stop_instance(self.tenant_id, self.auth_token, instance_id)
            time.sleep(10)
            instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            while instance_details["server"]["OS-EXT-STS:task_state"] == "powering-off":
                time.sleep(5)
                instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals("SHUTOFF", instance_details["server"]["status"])
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)
            content = utils.nova_start_instance(self.tenant_id, self.auth_token, instance_id)
            time.sleep(3)
            instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            while instance_details["server"]["OS-EXT-STS:task_state"] == "powering-on":
                time.sleep(5)
                instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals("ACTIVE", instance_details["server"]["status"])
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals("in-use", volume_details["volume"]["status"], "Volume is not in in-use state")


        def test_12(self):
            """ Attach boot volume_while_creating_instance """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create(self.tenant_id, self.auth_token,
                                        config.bootable_volume_name, config.bootable_volume_size, image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True,is_available)
            content = utils.volume_boot_attach_while_creating_instance(self.tenant_id, self.auth_token, volume_id,
                                                                    config.key_name, config.instance_name, config.flavor,
                                                                    config.network, config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True,is_active)
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id,volume_details["volume"]["attachments"][0]["server_id"],"Server id not found in volume details")



        def test_13(self):
            """ Write data on bootable volume """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create(self.tenant_id, self.auth_token, config.bootable_volume_name,
                                        config.bootable_volume_size_for_data, image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True, is_available)
            content = utils.volume_boot_attach_while_creating_instance(self.tenant_id, self.auth_token,
                                                                     volume_id,config.key_name, config.instance_name, config.flavor,                                                                            config.network,config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active)
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id, volume_details["volume"]["attachments"][0]["server_id"],"notequal")
            instance_ip = utils.floating_ip_associate(self.tenant_id, self.auth_token, "public", instance_id)
            time.sleep(30)
            size = config.volume_block_size
            count = config.count
            file_size = size*count
            utils.write_data_on_volume(instance_ip, size, count, "/")
            time.sleep(30)
            value = utils.is_file_exists(instance_ip,"/", file_size)
            self.assertEquals(True, value, "File not found")


        def test_14(self):
            """ Data on volume persists when attached to different instance """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name,
                                               config.network, config.security_group, config.instance_name)
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)
            instance_ip = utils.floating_ip_associate(self.tenant_id, self.auth_token, "public", instance_id)
            time.sleep(30)
            value = utils.create_filesystem(instance_ip, device, "/mnt/temp")
            self.assertEquals("Filesystem Created", value)
            value = utils.mount_volume(instance_ip, device, "/mnt/temp")
            self.assertEquals("Successfully mounted", value)
            size = config.volume_block_size
            count = config.count
            file_size = size*count
            utils.write_data_on_volume(instance_ip, size, count, "/mnt/temp")
            value = utils.is_file_exists(instance_ip, "/mnt/temp", file_size)
            self.assertEquals(True, value)
            value = utils.unmount_volume(instance_ip, "/mnt/temp")
            self.assertEquals("Successfully unmounted", value)
            value = utils.instance_delete(self.tenant_id, self.auth_token, instance_id)
            self.assertNotEqual(True, value)
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name, config.network,
                                               config.security_group, config.instance_name)
            instance_ip = utils.floating_ip_associate(self.tenant_id, self.auth_token, "public", instance_id)
            time.sleep(30)
            device = self.attach_volume(instance_id, volume_id)
            value = utils.mount_volume(instance_ip, device, "/mnt/temp")
            self.assertEquals("Successfully mounted", value)
            value = utils.is_file_exists(instance_ip, "/mnt/temp", file_size)
            self.assertEquals(True,value)


        def test_15(self):
            """ Negative-Attach same non bootable volume to multiple instance """
            instance_id_1 = self.create_instance(config.image_name, config.flavor, config.key_name,
                                                 config.network, config.security_group, config.instance_name+str(1))
            # instance_id_2 = self.create_instance(config.image_name, config.flavor, config.key_name,
            #                                      config.network, config.security_group, config.instance_name+str(2))
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            for instance_id in [instance_id_1, instance_id_1]:
                try:
                    device = self.attach_volume(instance_id, volume_id)
                except Exception as e:
                    self.assertIn("Invalid volume" and volume_id  and "available" and "in-use", str(e), "Exception not found")


        def test_16(self):
            """ Detach non bootable volume from running instance """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name, config.network,
                                             config.security_group, config.instance_name)
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)
            self.detach_volume(instance_id, volume_id)


        def test_17(self):
            """ Detach non bootable volume when instance is shut off """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name,
                                             config.network, config.security_group, config.instance_name) 
            content = utils.nova_stop_instance(self.tenant_id, self.auth_token, instance_id)
            time.sleep(10)
            instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            while instance_details["server"]["OS-EXT-STS:task_state"] == "powering-off":
                time.sleep(5)
                instance_details = utils.instance_details(self.tenant_id,self.auth_token,instance_id)
            self.assertEquals("SHUTOFF",instance_details["server"]["status"])
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            self.attach_volume(instance_id,volume_id)
            self.detach_volume(instance_id,volume_id)


        def test_18(self):
            """ Detach boot volume when vm is shutoff """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create(tenant_id=self.tenant_id, auth_token=self.auth_token,
                                          name=config.bootable_volume_name, size=config.bootable_volume_size, image_id=image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True,is_available)
            content = utils.volume_boot_attach_while_creating_instance(self.tenant_id, self.auth_token, volume_id, config.key_name,
                                                                       config.instance_name, config.flavor, config.network, config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active)
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id, volume_details["volume"]["attachments"][0]["server_id"], "Instance id not found in attachments")
            content = utils.nova_stop_instance(self.tenant_id, self.auth_token, instance_id)
            time.sleep(10)
            instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            while instance_details["server"]["OS-EXT-STS:task_state"] == "powering-off":
                time.sleep(5)
                instance_details = utils.instance_details(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals("SHUTOFF", instance_details["server"]["status"])
            try:
                content = utils.volume_detach(self.tenant_id, self.auth_token, instance_id, volume_id)
            except Exception as e:
                self.assertIn("Can\\\'t detach root device volume", str(e), "Exception not found")


        def test_19(self):
            """ Detach boot volume from running instance """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create(tenant_id=self.tenant_id, auth_token=self.auth_token,
                                        name=config.bootable_volume_name, size=config.bootable_volume_size, image_id=image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token,volume_id)
            self.assertEquals(True,is_available)
            content = utils.volume_boot_attach_while_creating_instance(self.tenant_id, self.auth_token, volume_id, config.key_name,
                                                                       config.instance_name, config.flavor, config.network, config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active)
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id, volume_details["volume"]["attachments"][0]["server_id"],"notequal")
            try:
                content = utils.volume_detach(self.tenant_id, self.auth_token, instance_id, volume_id)
            except Exception as e:
                self.assertIn("Can\\\'t detach root device volume", str(e), "Exception not found")
                

        def test_20(self):
            """ Delete non bootable volume """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name,
                                                        config.non_bootable_volume_size)
            value = utils.volume_delete(self.tenant_id, self.auth_token, volume_id)
            self.assertNotEqual(True, value)


        def test_21(self):
            """ Delete non bootable when attached to an instance """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name,
                                             config.network, config.security_group, config.instance_name) 
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)
            try:
                value = utils.volume_delete(self.tenant_id, self.auth_token, volume_id)
            except Exception as e:
                self.assertIn("Volume cannot be deleted while in attached state", str(e), "Exception not found")


        def test_22(self):
            """ Delete bootable volume """
            volume_id = self.create_bootable_volume(config.bootable_volume_name,
                                                    config.bootable_volume_size, config.image_name)          
            value = utils.volume_delete(self.tenant_id, self.auth_token, volume_id)
            self.assertNotEqual(True, value, "Volume is not deleted")


        def test_23(self):
            """ Delete instance with non- bootable volume attached """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name, config.network,
                                             config.security_group, config.instance_name)
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)
            value = utils.instance_delete(self.tenant_id, self.auth_token, instance_id)
            self.assertNotEqual(True, value, "Instance is not deleted")
            content = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals("available", content["volume"]["status"], "Volume is not in available state")


        def test_24(self):
            """ Delete instance when boot volume attached to instance with delete=false """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create(self.tenant_id, self.auth_token,
                                        config.bootable_volume_name, config.bootable_volume_size, image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True, is_available, "Instance is not deleted")
            content = utils.volume_boot_attach_while_creating_instance(self.tenant_id, self.auth_token,
                                                                     volume_id, config.key_name, config.instance_name, config.flavor,                                                                            config.network,config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active, "Instance is not active")
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id, volume_details["volume"]["attachments"][0]["server_id"], "notequal")
            value = utils.instance_delete(self.tenant_id, self.auth_token, instance_id)
            self.assertNotEqual(True, value, "Instance is not deleted")
            content = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals("available", content["volume"]["status"], "Volume is not in available state")


        def test_25(self):
            """ Delete instance when boot volume attached to instance with delete=true """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create(self.tenant_id, self.auth_token, config.bootable_volume_name, config.bootable_volume_size, image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True, is_available, "Volume is not in available state")
            content = utils.volume_boot_attach_while_creating_instance(self.tenant_id, self.auth_token,volume_id, config.key_name, config.instance_name,
                                                                       config.flavor, config.network, config.security_group, delete="true")
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token, instance_id)
            self.assertEquals(True, is_active, "Instance is not active")
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id, volume_details["volume"]["attachments"][0]["server_id"], "Instance id not found in atachments")
            value = utils.instance_delete(self.tenant_id, self.auth_token, instance_id)
            self.assertNotEqual(True,value)
            try:
                details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
                if details["volume"]["status"] == "in-use" or "available":
                    time.sleep(15)
                    while details["volume"]["status"] == "deleting":
                        time.sleep(5)
                        details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            except Exception as e:
                self.assertIn("Volume could not be found", str(e), "Exception not found")
                return None
            volumes = utils.volume_list(self.tenant_id, self.auth_token)
            for volume in range(len(volumes["volumes"])):
                self.assertNotEqual(volume_id, content["volumes"][volume]["id"], "Volume is not deleted")


        def test_26(self):
            """ Negative - Delete bootable volume in use """
            image_id = utils.image_id(self.tenant_id, self.auth_token, config.image_name)
            content = utils.volume_create(self.tenant_id, self.auth_token, config.bootable_volume_name, config.bootable_volume_size, image_id)
            volume_id = content["volume"]["id"]
            is_available = utils.is_volume_available(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(True,is_available)
            content = utils.volume_boot_attach_while_creating_instance(self.tenant_id, self.auth_token, volume_id, config.key_name, config.instance_name, config.flavor,
                                                                     config.network, config.security_group)
            instance_id = utils.instance_id(self.tenant_id, self.auth_token, config.instance_name)
            is_active = utils.is_instance_active(self.tenant_id, self.auth_token,instance_id)
            self.assertEquals(True, is_active)
            volume_details = utils.volume_details(self.tenant_id, self.auth_token, volume_id)
            self.assertEquals(instance_id, volume_details["volume"]["attachments"][0]["server_id"], "Instance id not found in attachments")
            try:
                value = utils.volume_delete(self.tenant_id, self.auth_token, volume_id)
            except Exception as e:
                self.assertIn("Volume cannot be deleted while in attached state", str(e), "Exception not found")


        def test_27(self):
            """ Data on volume persists even after the instance is deleted """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name,
                                               config.network, config.security_group, config.instance_name)
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)
            instance_ip = utils.floating_ip_associate(self.tenant_id, self.auth_token, "public", instance_id)
            time.sleep(30)
            value = utils.create_filesystem(instance_ip, device, "/mnt/temp")
            self.assertEquals("Filesystem Created", value)
            value = utils.mount_volume(instance_ip, device,"/mnt/temp")
            self.assertEquals("Successfully mounted", value)
            size = config.volume_block_size
            count = config.count
            file_size = size*count
            utils.write_data_on_volume(instance_ip, size, count, "/mnt/temp")
            time.sleep(30)
            value = utils.is_file_exists(instance_ip, "/mnt/temp", file_size)
            self.assertEquals(True ,value, "File not found")
            value = utils.instance_delete(self.tenant_id, self.auth_token, instance_id)
            self.assertNotEqual(True, value, "Instance not deleted")
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name,
                                               config.network, config.security_group, config.instance_name)
            instance_ip = utils.floating_ip_associate(self.tenant_id, self.auth_token, "public", instance_id)
            time.sleep(30)
            device = self.attach_volume(instance_id, volume_id)
            value = utils.mount_volume(instance_ip, device, "/mnt/temp")
            self.assertEquals("Successfully mounted", value)
            value = utils.is_file_exists(instance_ip, "/mnt/temp", file_size)
            self.assertEquals(True, value, "File not found")


        def test_28(self):
            """ Volume with maximum size and  minimum size """
            for size in [1,1000]:
                    volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name+str(size), size)
                    is_available = utils.is_volume_available(self.tenant_id,
                                                     self.auth_token, volume_id)
                    self.assertEquals(True, is_available,
                              "volume with size %s available state" % size)


        def test_29(self):
            """ Negative - Volume size greater than maximum size and less than minimum size """
            for size in [-1,1001]:
                try:
                    volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name+str(size), size)
                except Exception as e:
                    if size == -1:
                        self.assertIn("Invalid volume size provided" , str(e), "Exception not found")
                    elif size == 1001:
                        self.assertIn("Requested volume or snapshot exceeds allowed gigabytes quota", str(e), "Exception not found")


        def test_30(self):
            """  Create backup """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            backup_id = self.create_backup(volume_id, config.backup_name)


        def test_31(self):
          """ Negative - Backup when volume is in use """
          instance_id = self.create_instance(config.image_name, config.flavor, config.key_name, config.network, config.security_group, config.instance_name)
          volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
          self.attach_volume(instance_id, volume_id)
          try:
             backup_id = self.create_backup(volume_id, config.backup_name)
          except Exception as e:
             self.assertIn("Invalid volume: Volume to be backed up must be available" , str(e), "Exception not found")


        def test_32(self):
            """ Create maximum number of backups """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            for i in range(0, config.backup_limit):
                backup_name = config.backup_name+str(i)
                backup_id = self.create_backup(volume_id, backup_name)
                backup_list = utils.backup_list(self.tenant_id, self.auth_token)
            self.assertEquals(config.backup_limit, len(backup_list["backups"]), "Number of backups is not equal to the maximum limit")
                

        def test_33(self):
            """  Negative - create backup more than maximum limit """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            negative_limit = config.backup_limit+1
            for i in range(negative_limit):
                backup_name = config.backup_name+str(i)
                try:
                    backup_id = self.create_backup(volume_id, backup_name)
                except Exception as e:
                    self.assertIn("Maximum number of backups allowed (10) exceeded", str(e), "Exception not found")


        def test_34(self):
            """ Restore Backup """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            backup_id = self.create_backup(volume_id, config.backup_name)
            volume_id = self.restore_backup(backup_id)


        def test_35(self):
            """ Backup a volume with data when restored and attached to another instance data exists """
            instance_id = self.create_instance(config.image_name, config.flavor, config.key_name,
                                               config.network, config.security_group, config.instance_name)
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            device = self.attach_volume(instance_id, volume_id)
            instance_ip = utils.floating_ip_associate(self.tenant_id, self.auth_token, "public",instance_id)
            time.sleep(30)
            value = utils.create_filesystem(instance_ip, device, "/mnt/temp")
            self.assertEquals("Filesystem Created", value, "File system not created")
            value = utils.mount_volume(instance_ip, device, "/mnt/temp")
            self.assertEquals("Successfully mounted", value, "Volume is not mounted")
            size = config.volume_block_size
            count = config.count
            file_size = size*count
            utils.write_data_on_volume(instance_ip, size,count, "/mnt/temp")
            time.sleep(30)
            value = utils.is_file_exists(instance_ip,"/mnt/temp",file_size)
            self.assertEquals(True, value, "File not found")
            value = utils.unmount_volume(instance_ip, "/mnt/temp")
            self.assertEquals("Successfully unmounted", value, "Volume not mounted")
            value = utils.instance_delete(self.tenant_id, self.auth_token, instance_id)
            self.assertNotEqual(True, value, "Instance not deleted")
            backup_id = self.create_backup(volume_id, config.backup_name)
            volume_id = self.restore_backup(backup_id)
            instance_id = self.create_instance(config.image_name, config.flavor,
                                               config.key_name, config.network, config.security_group, config.instance_name)
            instance_ip = utils.floating_ip_associate(self.tenant_id, self.auth_token, "public", instance_id)
            time.sleep(30)
            device = self.attach_volume(instance_id, volume_id)
            value = utils.mount_volume(instance_ip, device, "/mnt/temp")
            self.assertEquals("Successfully mounted", value, "Volume not mounted")
            value = utils.is_file_exists(instance_ip, "/mnt/temp", file_size)
            self.assertEquals(True, value, "File doesnot exists")


        def test_36(self):
            """ Negative - Restore fails as exceeds the volume limit """
            for i in range(config.volume_limit):
                volume_name = config.non_bootable_volume_name+str(i)
                volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
                backup_id = self.create_backup(volume_id, config.backup_name)
            try:
                volume_id = self.restore_backup(backup_id)
            except Exception as e:
                self.assertIn("Maximum number of volumes allowed (10) exceeded", str(e), "Exception not found")


        def test_37(self):
            """ Check backup ids are unique """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            backup_id_1 = self.create_backup(volume_id, config.backup_name+str(1))
            backup_id_2 = self.create_backup(volume_id, config.backup_name+str(2))
            self.assertNotEqual(backup_id_1, backup_id_2, "Backup id's are unique")


        def test_38(self):
            """ Delete Backup """
            volume_id = self.create_non_bootable_volume(config.non_bootable_volume_name, config.non_bootable_volume_size)
            backup_id = self.create_backup(volume_id, config.backup_name)
            value = utils.backup_delete(self.tenant_id, self.auth_token, backup_id)
            self.assertNotEqual(True, value, "Backup is not deleted")


        def tearDown(self):
            instances = utils.instance_list(self.tenant_id, self.auth_token)
            if len(instances["servers"])>0:
                for instance in range(len(instances["servers"])):
                    instance_id = instances["servers"][instance]["id"]
                    value = utils.instance_delete(self.tenant_id, self.auth_token, instance_id)
                    self.assertNotEqual(True, value, "Instance not deleted")
            floating_ips = utils.floating_ip_list(self.tenant_id, self.auth_token)
            if len(floating_ips["floatingips"])>0:
                    for ip  in range(len(floating_ips["floatingips"])):
                        ip_id = floating_ips["floatingips"][ip]["id"]
                        value = utils.floating_ip_delete(self.tenant_id, self.auth_token, ip_id)
                        self.assertNotEqual(True, value, "IP not deleted")
            volumes = utils.volume_list(self.tenant_id, self.auth_token)
            if len(volumes["volumes"])>0:
                for volume in range(len(volumes["volumes"])):
                    volume_id = volumes["volumes"][volume]["id"]
                    value = utils.volume_delete(self.tenant_id, self.auth_token, volume_id)
                    self.assertNotEqual(True, value,"Volume not deleted")
            backups = utils.backup_list(self.tenant_id, self.auth_token)
            if len(backups["backups"])>0:
                for backup in range(len(backups["backups"])):
                    backup_id = backups["backups"][backup]["id"]
                    value = utils.backup_delete(self.tenant_id, self.auth_token, backup_id)
                    self.assertNotEqual(True ,value, "Backup not deleted")
                    
           
    suite = unittest.TestLoader().loadTestsFromTestCase(Functional_tests)
    testResult = unittest.TextTestRunner(verbosity=2).run(suite)
    errors = testResult.errors
    failures = testResult.failures
    return errors, failures


if __name__ == "__main__":
    main()

