pragma solidity ^0.8.0;

contract ControlIOT {
    address public owner;
    address public subject;
    address public object;
    Decision public jc;

    event ReturnAccessResult(
        address indexed _from,
        string _errmsg,
        bool _result,
        uint256 _time,
        uint256 _penalty
    );

    struct Problem {
        string res;
        string action;
        string problem;
        uint256 time;
        uint256 penalty;
    }

    struct BehaviorItem {
        Problem[] mbs;
        uint256 TimeofUnblock;
    }

    struct PolicyItem {
        bool isValued;
        string permission;
        uint256 minInterval;
        uint256 ToLR;
        uint256 NoFR;
        uint256 threshold;
        bool result;
        uint8 err;
    }

    mapping(bytes32 => mapping(bytes32 => PolicyItem)) policies;
    mapping(bytes32 => BehaviorItem) behaviors;

    function stringToBytes32(string _str) public returns (bytes32) {
        bytes memory tempBytes = bytes(_str);
        bytes32 convertedBytes;
        if (0 == tempBytes.length) {
            return 0x0;
        }
        assembly {
            convertedBytes := mload(add(_str, 32))
        }
        return convertedBytes;
    }

    function AccessControlMethod(address _subject) public {
        owner = msg.sender;
        object = msg.sender;
        subject = _subject;
    }

    function setJC(address _jc) public {
        if (owner == msg.sender) {
            jc = Decision(_jc);
        }  
    }

    function policyAdd(
        string _resource,
        string _action,
        string _permission,
        uint256 _minInterval,
        uint256 _threshold
    ) public {
        bytes32 resource = stringToBytes32(_resource);
        bytes32 action = stringToBytes32(_action);
        if (msg.sender == owner) {
            if (!(policies[resource][action].isValued)  )
             {
                policies[resource][action].permission = _permission;
                policies[resource][action].minInterval = _minInterval;
                policies[resource][action].threshold = _threshold;
                policies[resource][action].ToLR = 0;
                policies[resource][action].NoFR = 0;
                policies[resource][action].isValued = true;
                policies[resource][action].result = false;
                behaviors[resource].TimeofUnblock = 0;
            }
        }  
    }

    function getPolicy(string _resource, string _action)
        public
        returns (
            string _permission,
            uint256 _minInterval,
            uint256 _threshold,
            uint256 _ToLR,
            uint256 _NoFR,
            bool _res,
            uint8 _errcode
        )
    {
        bytes32 resource = stringToBytes32(_resource);
        bytes32 action = stringToBytes32(_action);
        if (policies[resource][action].isValued) {
            _permission = policies[resource][action].permission;
            _minInterval = policies[resource][action].minInterval;
            _threshold = policies[resource][action].threshold;
            _NoFR = policies[resource][action].NoFR;
            _ToLR = policies[resource][action].ToLR;
            _res = policies[resource][action].result;
            _errcode = policies[resource][action].err;
        }  
    }

    function policyUpdate(
        string _resource,
        string _action,
        string _newPermission
    ) public {
        bytes32 resource = stringToBytes32(_resource);
        bytes32 action = stringToBytes32(_action);
        if (policies[resource][action].isValued) {
            policies[resource][action].permission = _newPermission;
        }  
    }

    function minIntervalUpdate(
        string _resource,
        string _action,
        uint256 _newMinInterval
    ) public {
        bytes32 resource = stringToBytes32(_resource);
        bytes32 action = stringToBytes32(_action);
        if (policies[resource][action].isValued) {
            policies[resource][action].minInterval = _newMinInterval;
        }  
    }

    function thresholdUpdate(
        string _resource,
        string _action,
        uint256 _newThreshold
    ) public {
        bytes32 resource = stringToBytes32(_resource);
        bytes32 action = stringToBytes32(_action);
        if (policies[resource][action].isValued) {
            policies[resource][action].threshold = _newThreshold;
        } 
    }

    function policyDelete(string _resource, string _action) public {
        bytes32 resource = stringToBytes32(_resource);
        bytes32 action = stringToBytes32(_action);
        if (msg.sender == owner) {
            if (policies[resource][action].isValued) {
                delete policies[resource][action];
            }  
        }  
    }

    /*Use event*/
    function accessControl(
        string _resource,
        string _action,
        uint256 _time
    ) public {
        bool policycheck = false;
        bool behaviorcheck = true;
        uint8 errcode = 0;
        uint256 penalty = 0;

        if (msg.sender == subject) {
            bytes32 resource = stringToBytes32(_resource);
            bytes32 action = stringToBytes32(_action);

            if (behaviors[resource].TimeofUnblock >= _time) {
                errcode = 1;
            } else {
                if (behaviors[resource].TimeofUnblock > 0) {
                    behaviors[resource].TimeofUnblock = 0;
                    policies[resource][action].NoFR = 0;
                    policies[resource][action].ToLR = 0;
                }

                if (
                    keccak256("allow") ==
                    keccak256(policies[resource][action].permission)
                ) {
                    policycheck = true;
                } else {
                    policycheck = false;
                }

                if (
                    _time - policies[resource][action].ToLR <=
                    policies[resource][action].minInterval
                ) {
                    policies[resource][action].NoFR++;
                    if (
                        policies[resource][action].NoFR >=
                        policies[resource][action].threshold
                    ) {
                        penalty = jc.lawyer(
                            subject,
                            object,
                            _resource,
                            _action,
                            "Too frequent access!",
                            _time
                        );
                        behaviorcheck = false;
                        behaviors[resource].TimeofUnblock =
                            _time +
                            penalty *
                            1 minutes;
                        behaviors[resource].mbs.push(
                            Problem(
                                _resource,
                                _action,
                                "Too frequent access!",
                                _time,
                                penalty
                            )
                        );
                    }
                } else {
                    policies[resource][action].NoFR = 0;
                }
                if (!policycheck && behaviorcheck) errcode = 2;
                if (policycheck && !behaviorcheck) errcode = 3;
                if (!policycheck && !behaviorcheck) errcode = 4;
            }
            policies[resource][action].ToLR = _time;
        } else {
            errcode = 5;
        }
    
        if (0 == errcode)
            ReturnAccessResult(
                msg.sender,
                "Access authorized!",
                true,
                _time,
                penalty
            );
        if (1 == errcode)
            ReturnAccessResult(
                msg.sender,
                "Requests are blocked!",
                false,
                _time,
                penalty
            );
        if (2 == errcode)
            ReturnAccessResult(
                msg.sender,
                "Static Check failed!",
                false,
                _time,
                penalty
            );
        if (3 == errcode)
            ReturnAccessResult(
                msg.sender,
                "Problem detected!",
                false,
                _time,
                penalty
            );
        if (4 == errcode)
            ReturnAccessResult(
                msg.sender,
                "Static check failed! & Problem detected!",
                false,
                _time,
                penalty
            );
        if (5 == errcode)
            ReturnAccessResult(
                msg.sender,
                "Wrong object or subject specified!",
                false,
                _time,
                penalty
            );
    }

    function getTimeofUnblock(string _resource)
        public
        returns (uint256 _penalty, uint256 _timeOfUnblock)
    {
        bytes32 resource = stringToBytes32(_resource);
        _timeOfUnblock = behaviors[resource].TimeofUnblock;
        uint256 l = behaviors[resource].mbs.length;
        _penalty = behaviors[resource].mbs[l - 1].penalty;
    }

    function deleteACC() public {
        if (msg.sender == owner) {
            selfdestruct(this);
        }
    }
}

contract Decision {
    uint256 public base;
    uint256 public interval;
    address public owner;

    event isCalled(address _from, uint256 _time, uint256 _penalty);

    struct Problem {
        address subject;
        address object;
        string res;
        string action;
        string problem;
        uint256 time;
        uint256 penalty;
    }

    mapping(address => Problem[]) public ProblemList;
    function Judge(uint256 _base, uint256 _interval) public {
        base = _base;
        interval = _interval;
        owner = msg.sender;
    }

    function lawyer(
        address _subject,
        address _object,
        string _res,
        string _action,
        string _problem,
        uint256 _time
    ) public returns (uint256 penalty) {
        uint256 length = ProblemList[_subject].length + 1;
        uint256 n = length / interval;
        penalty = base**n;
        ProblemList[_subject].push(
            Problem(_subject, _object, _res, _action, _problem, _time, penalty)
        );
        isCalled(msg.sender, _time, penalty);
    }

    function getLatestProblem(address _key)
        public
        returns (
            address _subject,
            address _object,
            string _res,
            string _action,
            string _problem,
            uint256 _time
        )
    {
        uint256 latest = ProblemList[_key].length - 1;

        _subject = ProblemList[_key][latest].subject;
        _object = ProblemList[_key][latest].object;
        _res = ProblemList[_key][latest].res;
        _action = ProblemList[_key][latest].action;
        _problem = ProblemList[_key][latest].problem;
        _time = ProblemList[_key][latest].time;
    }

    function self_destruct() public {
        if (msg.sender == owner) {
            selfdestruct(this);
        }
    }
}

contract Register {
    struct Method {
        string scName;
        address subject;
        address object;
        address creator;
        address scAddress;
        bytes abi;
    }

    mapping(bytes32 => Method) public lookupTable;

    function stringToBytes32(string _str) public returns (bytes32) {
        bytes memory tempBytes = bytes(_str);
        bytes32 convertedBytes;
        if (0 == tempBytes.length) {
            return 0x0;
        }
        assembly {
            convertedBytes := mload(add(_str, 32))
        }
        return convertedBytes;
    }

    function methodRegister(
        string _methodName,
        string _scname,
        address _subject,
        address _object,
        address _creator,
        address _scAddress,
        bytes _abi
    ) public {
        bytes32 newKey = stringToBytes32(_methodName);
        lookupTable[newKey].scName = _scname;
        lookupTable[newKey].subject = _subject;
        lookupTable[newKey].object = _object;
        lookupTable[newKey].creator = _creator;
        lookupTable[newKey].scAddress = _scAddress;
        lookupTable[newKey].abi = _abi;
    }

    function methodScNameUpdate(string _methodName, string _scName) public {
        bytes32 key = stringToBytes32(_methodName);
        lookupTable[key].scName = _scName;
    }

    function methodAcAddressUpdate(string _methodName, address _scAddress)
        public
    {
        bytes32 key = stringToBytes32(_methodName);
        lookupTable[key].scAddress = _scAddress;
    }

    function methodAbiUpdate(string _methodName, bytes _abi) public {
        bytes32 key = stringToBytes32(_methodName);
        lookupTable[key].abi = _abi;
    }

    function methodNameUpdate(string _oldName, string _newName) public {
        bytes32 oldKey = stringToBytes32(_oldName);
        bytes32 newKey = stringToBytes32(_newName);
        lookupTable[newKey].scName = lookupTable[oldKey].scName;
        lookupTable[newKey].subject = lookupTable[oldKey].subject;
        lookupTable[newKey].object = lookupTable[oldKey].object;
        lookupTable[newKey].creator = lookupTable[oldKey].creator;
        lookupTable[newKey].scAddress = lookupTable[oldKey].scAddress;
        lookupTable[newKey].abi = lookupTable[oldKey].abi;
        delete lookupTable[oldKey];
    }

    function methodDelete(string _name) public {
        delete lookupTable[stringToBytes32(_name)];
    }

    function getContractAddr(string _methodName)
        public
        returns (address _scAddress)
    {
        bytes32 key = stringToBytes32(_methodName);
        _scAddress = lookupTable[key].scAddress;
    }

    function getContractAbi(string _methodName) public returns (bytes _abi) {
        bytes32 key = stringToBytes32(_methodName);
        _abi = lookupTable[key].abi;
    }
}
