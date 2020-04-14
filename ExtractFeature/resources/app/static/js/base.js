let Server = function () {
};

// <template slot-scope="scope">
//     <el-button icon="el-icon-plus" @click="addBlackList(scope.$index)" plain={true}
// :loading="loadingGroup.addBlackLoading" size = "mini">加入黑名单
//     </el-button>
//
//     </template>

Server.prototype.sendMessage = function (name, payload, callback) {
    // console.log("sendMessage:", name, payload);
    // send a message to Go
    astilectron.sendMessage({ name: name, payload: payload }, function (message) {
        // console.log("response:", name, message);
        callback(message.payload)
    });
};

(function () {
    let system = {
        // current group name
        currentPanelName: '监控',
        // current group config
        currentGroupConfig: {},
        // table rows depended on this variable
        currentList: [], //[{ip:"1", domain: "a", enabled: true}],
        // put system hosts at here
        systemHosts: []
    };
    let server = new Server();
    let app = new Vue({
        el: '#app',
        data: {
            page: {
                pageSize: 10,
                currentPage: 1
            },
            loadingGroup: {
                menuLoading: false,
                fullscreenLoading: false,
                addBlackLoading: false,
                removeBlackLoading: false,
                refreshRemoteLoading: {}
            },
            selectionItemIndexes: [],
            menuList: [
                {
                    name: "监控", active: true,
                    connList: []
                },
            ],
            system: system,
        },
        methods: {
            handleSelectionChange(rows) {
                this.selectionItemIndexes = [];
                rows.forEach((item) => {
                    this.selectionItemIndexes.push(item.index)
                });
                // console.log(this.selectionItemIndexes)
            },
            tableRowClassName(row) {
                row.row.index = row.rowIndex;
            },
            handleCurrentChange: function (currentPage) {
                this.page.currentPage = currentPage;
            },
            selectMenu: function (menuName) {
                if (!this.loadingGroup.refreshRemoteLoading.hasOwnProperty(menuName)) {
                    //add the loading key to vue monitor
                    this.$set(this.loadingGroup.refreshRemoteLoading, menuName, false);
                }
                this.page.currentPage = 1;
                this.loadingGroup.menuLoading = true;
                for (let i in this.menuList) {
                    let item = this.menuList[i];
                    if (menuName === item.name) {
                        item.active = true;

                        if (item.connList === null) {
                            this.menuList[i].connList = []
                        }
                        this.system.currentList = item.connList;
                        // this.system.currentGroupConfig = item.groupConfig;

                        this.system.currentPanelName = item.name;
                    } else {
                        item.active = false;
                    }
                }
                this.loadingGroup.menuLoading = false;
            },
            addBlackList: function (ip) {
                server.sendMessage("addBlackList", { ip: ip }, (message) => {
                    if (message.code === 1) {
                        console.log("加入黑名单成功！")
                    }
                })
            },
            removeBlackList: function (ip) {
                server.sendMessage("removeBlackList", { ip: ip }, (message) => {
                    if (message.code === 1) {
                        console.log("成功移除黑名单！")
                    }
                })
            },
            fixIndexOffset: function (index) {
                return (this.page.currentPage - 1) * this.page.pageSize + index
            },
            changeHost: function (value, index) {
                let ip;
                let enabled;
                index = this.fixIndexOffset(index);
                if (this.system.currentPanelName === '监控') {
                    ip = this.menuList[0].connList[index].ip;
                    enabled = this.menuList[0].connList[index].enabled;
                }

                if (enabled) {
                    this.addBlackList(ip);
                } else {
                    this.removeBlackList(ip);
                }

            }
        },
        created() {
            document.addEventListener('astilectron-ready', () => {
                //listen the message from backend
                astilectron.onMessage((message) => {
                    // console.log("receive message: ", message.name, message);
                    switch (message.name) {
                        case 'hostList':
                            if (message.payload == null) {
                                break
                            }

                            let index;
                            for (let i in this.menuList[0].connList) {
                                if (this.menuList[0].connList[i].ip === message.payload.ip) {
                                    index = i;
                                    this.menuList[0].connList.splice(index, 1);
                                    break;
                                }
                            }

                            this.menuList[0].connList.unshift({
                                ip: message.payload.ip,
                                connNum: message.payload.connNum,
                                abnormalRate: message.payload.abnormalRate,
                                attackType: message.payload.attackType,
                                enabled: message.payload.enabled,
                            });
                            if (this.system.currentPanelName === '监控') {
                                this.system.currentList = this.menuList[0].connList;

                                this.system.currentPanelName = this.menuList[0].name;
                            }

                            break;
                    }
                });
            })
        }
    });
})();
