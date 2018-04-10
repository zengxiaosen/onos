package org.onosproject.fwd;

/**
 * Created by lihaifeng on 18-4-10.
 */

import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;
import org.apache.karaf.shell.commands.Argument;
import org.onlab.packet.MacAddress;

/**
 *  根据IP地址找出路径
 */
@Command(scope = "onos", name = "fwd-spbi",
        description = "根据输入的IP地址对查找路径")
public class SearchPathByIpCommand extends AbstractShellCommand{

    @Argument(index = 0, name = "ipSrc", description = "源IP地址",
            required = true, multiValued = false)
    String ipSrc = null;
    @Argument(index = 1, name = "ipDst", description = "目的IP地址",
            required = true, multiValued = false)
    String ipDst = null;

    @Override
    protected void execute() {
        ReactiveForwarding reactiveForwardingService = AbstractShellCommand.get(ReactiveForwarding.class);
        MacAddress macAddress = null;
        if (ipDst != null&&ipSrc!=null) {
            System.out.println("========================   SearchPathByIpCommand   =============================");
            String path = reactiveForwardingService.getPathByIp(ipSrc,ipDst);
            System.out.println(path);
            System.out.println("=============================================================================");
        }else {
            System.out.println("========================   参数错误   =============================");
        }
    }
}
