import {IBonsaiProxy} from "./IBonsaiProxy.sol";

pragma solidity ^0.8.16;

contract BonsaiProxy is IBonsaiProxy {
    constructor() {}

    function submit_request(
        bytes32 image_id,
        bytes calldata input,
        address callback_address
    ) external {
        //   TODO
    }
}
