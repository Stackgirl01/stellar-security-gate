#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    // BUG: takes an Address but never calls require_auth() — anyone can
    // withdraw on behalf of any address.
    pub fn withdraw(env: Env, from: Address, amount: i128) {
        let balance: i128 = env.storage().instance().get(&from).unwrap();
        let new_balance = balance - amount;
        env.storage().instance().set(&from, &new_balance);
    }

    // BUG: unwrap() on a value that may not exist.
    pub fn get_balance(env: Env, who: Address) -> i128 {
        env.storage().instance().get(&who).unwrap()
    }

    // OK: correctly checks auth before mutating state.
    pub fn deposit(env: Env, to: Address, amount: i128) {
        to.require_auth();
        let balance: i128 = env.storage().instance().get(&to).unwrap_or(0);
        env.storage().instance().set(&to, &(balance + amount));
    }
}
