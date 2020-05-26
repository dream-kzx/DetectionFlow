# coding=utf-8
import numpy as np
from GenerateModel import type as AttackType

class FlowFeature:
    def __init__(self, request):
        self.duration = request.duration
        self.protocolType = request.protocolType
        self.service = request.service
        self.flag = request.flag
        self.srcBytes = request.srcBytes
        self.dstBytes = request.dstBytes
        self.land = request.land
        self.wrongFragment = request.wrongFragment
        self.urgent = request.urgent

        self.host = request.host
        self.numFailedLogins = request.numFailedLogins
        self.loggedIn = request.loggedIn
        self.numCompromised = request.numCompromised
        self.rootShell = request.rootShell
        self.suAttempted = request.suAttempted
        self.numRoot = request.numRoot
        self.numFileCreations = request.numFileCreations
        self.numShells = request.numShells
        self.numAccessFiles = request.numAccessFiles
        self.numOutboundCmds = request.numOutboundCmds
        self.isHotLogin = request.isHotLogin
        self.isGuestLogin = request.isGuestLogin

        self.count = request.count
        self.srvCount = request.srvCount
        self.sErrorRate = request.sErrorRate
        self.srvSErrorRate = request.srvSErrorRate
        self.rErrorRate = request.rErrorRate
        self.srvRErrorRate = request.srvRErrorRate
        self.sameSrvRate = request.sameSrvRate
        self.diffSrvRate = request.diffSrvRate
        self.srvDiffHostRate = request.srvDiffHostRate

        self.dstHostCount = request.dstHostCount
        self.dstHostSrvCount = request.dstHostSrvCount
        self.dstHostSameSrvRate = request.dstHostSameSrvRate
        self.dstHostDiffSrvRate = request.dstHostDiffSrvRate
        self.dstHostSameSrcPortRate = request.dstHostSameSrcPortRate
        self.dstHostSrvDiffHostRate = request.dstHostSrvDiffHostRate
        self.dstHostSErrorRate = request.dstHostSErrorRate
        self.dstHostSrvSErrorRate = request.dstHostSrvSErrorRate
        self.dstHostRErrorRate = request.dstHostRErrorRate
        self.dstHostSrvRErrorRate = request.dstHostSrvRErrorRate

    def toNpArray(self):
        # array = [[self.duration, self.protocolType, self.service, self.flag, self.srcBytes, self.dstBytes, self.land,
        #          self.wrongFragment, self.urgent, self.host, self.numFailedLogins, self.loggedIn, self.numCompromised,
        #          self.rootShell, self.suAttempted, self.numRoot, self.numFileCreations, self.numShells,
        #          self.numAccessFiles, self.numOutboundCmds, self.isHotLogin, self.isGuestLogin, self.count,
        #          self.srvCount, self.sErrorRate, self.srvSErrorRate, self.rErrorRate, self.srvRErrorRate,
        #          self.sameSrvRate, self.diffSrvRate, self.srvDiffHostRate, self.dstHostCount, self.dstHostSrvCount,
        #          self.dstHostSameSrvRate, self.dstHostDiffSrvRate, self.dstHostSameSrcPortRate,
        #          self.dstHostSrvDiffHostRate, self.dstHostSErrorRate, self.dstHostSrvSErrorRate, self.dstHostRErrorRate,
        #          self.dstHostSrvRErrorRate]]
        #array = [[self.protocolType, self.service, self.flag, self.srcBytes,
        #          self.sameSrvRate, self.dstHostSrvCount, self.dstHostSameSrvRate,
        #          self.dstHostDiffSrvRate, self.dstHostSrvSErrorRate]]
        array = [[self.duration, self.protocolType, self.service, AttackType.Flag.Type[self.flag], self.srcBytes,self.dstBytes,
                    self.srvSErrorRate,self.srvRErrorRate, self.sameSrvRate, self.diffSrvRate,
                    self.dstHostSameSrvRate, self.dstHostDiffSrvRate, self.dstHostSrvSErrorRate,self.dstHostSrvRErrorRate]]
        return np.array(array)
