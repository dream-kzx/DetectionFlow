let Server = function () {
};

Server.prototype.sendMessage = function (name, payload, callback) {
    console.log("sendMessage:", name, payload);
    // send a message to Go
    astilectron.sendMessage({name: name, payload: payload}, function (message) {
        console.log("response:", name, message);
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
                {
                    name: "处理记录", active: false,
                    connList: []
                }
            ],
            system: system,
        },
        methods: {
            handleSelectionChange(rows) {
                this.selectionItemIndexes = [];
                rows.forEach((item) => {
                    this.selectionItemIndexes.push(item.index)
                });
                console.log(this.selectionItemIndexes)
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
            }
        },
        created() {
            document.addEventListener('astilectron-ready', () => {

                //listen the message from backend
                astilectron.onMessage((message) => {
                    console.log("receive message: ", message.name, message);
                    switch (message.name) {
                        case 'hostList':
                            if (message.payload == null) {
                                break
                            }

                            let index;
                            for (let i in this.menuList[0].connList){
                                if(this.menuList[0].connList[i].ip === message.payload.ip){
                                    index = i;
                                    this.menuList[0].connList.splice(index,1);
                                    break;
                                }
                            }

                            this.menuList[0].connList.unshift({
                                ip: message.payload.ip ,
                                connNum: message.payload.connNum,
                                abnormalRate: message.payload.abnormalRate,
                                attackType: message.payload.attackType,
                            });
                            if (this.system.currentPanelName === '监控') {
                                this.system.currentList = this.menuList[0].connList;
                                // this.system.currentGroupConfig = item.groupConfig;

                                this.system.currentPanelName = this.menuList[0].name;
                            }

                        case 'connectionList':
                    }
                });
            })
        }
    });
})();