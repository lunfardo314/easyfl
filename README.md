This package is in **alpha**.

# EasyFL
**EasyFL** stands for **Easy** **F**ormula **L**anguage or **Easy** **F**unctional **L**anguage.
It is a very simple functional programming language. It is extendable, platform-independent, minimalistic and human-readable.
The expressions of the language take one of the following forms:
* _source form_, a human-readable ASCII form
* _canonical bytecode form_. The canonical bytecode is normally compiled from the source. It is the main form in which _EasyFL_ expressions are
  stored as part of data structures. Source code and execution form are created from it.
  Canonical bytecode form is highly compressed and therefore is ideal for inline embedding into the binary data structures.
* _internal execution_ form

Primary use of *EasyFL* is serialization of bounded data structures, composed at the binary raw byte level together with their validation code.
The serialized binary data include _EasyFL_ bytecode, which is an interpretable self-describing definition of finite validity constraints
as part of the serialized data structure.

_EasyFL_ was designed with programmability of the UTXO ledger and transactions in mind.
The _EasyFL_ validity scripts, being part of transaction outputs (UTXOs), enforce certain, pre-programmed behavior of the transactions which
consume them. An example may be signature lock constraint, which, when added to the output, invalidates any transactions which
attempts to consume it without providing a valid signature.

The *EasyFL* programmability may also be seen as a rudimentary form of smart contracts,
however in our opinion, the _UTXO constraints_ or _UTXO scripts_ is a better name for it.

Computationally, _EasyFL_ is equivalent to the _Bitcoin Script_ and equivalent models, i.e. its computational model is
non-Turing complete. _EasyFL_ can describe validity constraints of static data structures with known bounds, i.e. as _circuits_.

Non-Turing complete computational model of *EasyFL* makes it possible automatic proofs and validation of the ledger state transitions constrained by the _EasyFL_ constraints.
The constraint-based programmability of the ledger model does not require gas budgets and similar models to put the execution bounds on the program.

Here is a [preliminary language presentation](https://hackmd.io/@Evaldas/S14WHOKMi) of the **EasyFL** language and [Medium series on constraint-based UTXO model](https://medium.com/@lunfardo/a-constraint-based-utxo-model-1-4-a61df1b0c724) .  