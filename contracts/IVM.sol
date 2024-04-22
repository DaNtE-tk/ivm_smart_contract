//SPDX-License-Identifier:UNLICENSED

pragma solidity ^0.8.19;

contract IVM_Final {
    address public owner;

    struct userInfo {
        string name;
        uint256 dateOfBirth;
        string addr;
        string image;
        bool isVerified;
        string validationToken;
    }

    struct Request {
        address requester;
        address requestedUser;
        bool isAccepted;
        uint256 timestamp; // Timestamp when the request was accepted
        uint256 accessTime; // Custom access time for the request
    }

    mapping(address => userInfo) public users;
    mapping(address => mapping(address => bool)) public allowedToAccess;
    mapping(address => bool) public userExists;
    mapping(address => Request[]) public requests;
    mapping(address => bool) public isValidator;

    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "Only contract owner can perform this action"
        );
        _;
    }

    modifier onlyOwnerOrValidator() {
        require(
            msg.sender == owner || isValidator[msg.sender],
            "Only contract owner or validator can perform this action"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setUserAsValidator(address _userAddress)
        external
        onlyOwnerOrValidator
    {
        isValidator[_userAddress] = true;
    }

    function generateUUID(address _address)
        internal
        view
        returns (string memory)
    {
        bytes32 uuid = keccak256(
            abi.encodePacked(block.timestamp, block.prevrandao, _address)
        );
        return bytes12ToHexString(bytes12(uuid));
    }

    function bytes12ToHexString(bytes12 _bytes12)
        internal
        pure
        returns (string memory)
    {
        bytes memory bytesArray = new bytes(24);
        for (uint256 i = 0; i < 12; i++) {
            bytesArray[i * 2] = byteToHex(uint8(_bytes12[i] >> 4));
            bytesArray[i * 2 + 1] = byteToHex(uint8(_bytes12[i] & 0x0f));
        }
        return string(bytesArray);
    }

    function byteToHex(uint8 _byte) internal pure returns (bytes1) {
        if (_byte < 10) {
            return bytes1(uint8(_byte) + 48);
        } else {
            return bytes1(uint8(_byte) + 87);
        }
    }

    function verifyUser(address _userAddress) external {
        require(
            isValidator[msg.sender] || msg.sender == owner,
            "Only the owner or a validator can verify users"
        );
        userInfo storage user = users[_userAddress];
        require(bytes(user.name).length > 0, "User does not exist");
        require(!user.isVerified, "User is already verified");

        // Generate a pseudo-random token based on current timestamp and user's address

        user.isVerified = true;
        user.validationToken = generateUUID(_userAddress);
        // user.validationToken = _validationToken;
    }

    event AccountCreated(
        address indexed userAddress,
        string name,
        uint256 age,
        string addr,
        string image
    );
    event AccessRequested(
        address indexed requester,
        address indexed requestedUser
    );
    event AccessGranted(
        address indexed requested,
        address indexed requestedUser
    );

    function createUser(
        string memory _name,
        uint256 _dateOfBirth,
        string memory _addr,
        string memory _image
    ) external {
        require(bytes(_name).length > 0, "Name must not be empty");
        require(bytes(_addr).length > 0, "Address must not be empty");
        require(!userExists[msg.sender], "User already exists");

        require(
            _dateOfBirth <= block.timestamp - 220898880,
            "User must be atleast 7 years old"
        );

        address accountAddress = msg.sender;
        bool _isVerified = false;
        string memory _validationToken = "";
        users[accountAddress] = userInfo(
            _name,
            _dateOfBirth,
            _addr,
            _image,
            _isVerified,
            _validationToken
        );
        userExists[msg.sender] = true;

        emit AccountCreated(accountAddress, _name, _dateOfBirth, _addr, _image);
    }

    function sendAccessRequest(address _requestedUser) external {
        require(_requestedUser != address(0), "Invalid user address");
        require(userExists[_requestedUser], "User does not exist");

        address requester = msg.sender;
        requests[_requestedUser].push(
            Request(requester, _requestedUser, false, 0, 0)
        );
        emit AccessRequested(requester, _requestedUser);
    }

    function grantAccess(address _requester, uint256 _customAccessTime)
        external
    {
        require(
            bytes(users[msg.sender].name).length > 0,
            "User does not exist"
        );

        for (uint256 i = 0; i < requests[msg.sender].length; i++) {
            if (requests[msg.sender][i].requester == _requester) {
                allowedToAccess[_requester][msg.sender] = true;
                requests[msg.sender][i].isAccepted = true;
                requests[msg.sender][i].timestamp = block.timestamp; // Store the timestamp when access was granted

                // Set custom access time if provided, otherwise use default access time limit
                if (_customAccessTime > 0) {
                    requests[msg.sender][i].accessTime = _customAccessTime;
                } else {
                    requests[msg.sender][i].accessTime = 2 days; // Default access time limit
                }

                emit AccessGranted(_requester, msg.sender);
                break;
            }
        }
    }

    function getUserInfo(address _userAddress)
        external
        view
        returns (userInfo memory)
    {
        require(
            bytes(users[_userAddress].name).length > 0,
            "User does not exist"
        );

        require(
            allowedToAccess[msg.sender][_userAddress],
            "Access not granted"
        );

        // Check if access was granted and within the time limit
        uint256 accessTime = requests[_userAddress][0].accessTime;
        if (accessTime == 0) {
            // Use default access time limit if custom access time is not provided
            accessTime = 2 days;
        }
        require(
            allowedToAccess[msg.sender][_userAddress] &&
                isWithinTimeLimit(
                    requests[_userAddress][0].timestamp,
                    accessTime
                ),
            "Access not granted or time limit exceeded"
        );

        return users[_userAddress];
    }

    function isWithinTimeLimit(uint256 _timestamp, uint256 _timeLimit)
        internal
        view
        returns (bool)
    {
        return block.timestamp <= _timestamp + _timeLimit;
    }

    function myInfo() external view returns (userInfo memory) {
        address sender = msg.sender;
        userInfo memory senderInfo = users[sender];

        require(
            bytes(senderInfo.name).length > 0,
            "No information found for the sender's address"
        );

        return senderInfo;
    }

    function getIncomingRequests() external view returns (Request[] memory) {
        return requests[msg.sender];
    }
}
