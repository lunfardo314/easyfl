This package is a **work in progress**

# EasyFL
**EasyFL** stands for **Easy** **F**ormula **L**anguage or **Easy** **F**unctional **L**anguage. 
It is a very simple functional programming language. It is extendable, platform-independent, minimalistic and human-readable. 
The expressions of the language take one of the following forms:
* _source form_, a the human-readable ASCII form
* _canonical binary form_. The canonical binary is normally compiled from the source. It is a main form in which EasyFL expressions are
stored. Source code and execution form are created from it. Canonical binary form is highly compressed and ideal for inline 
embedding into the data structures. 
* _internal execution_ form.

The primary use of *EasyFL* is definition of finite constraints of bounded data structures, such as UTXO transactions. 
It was designed with programmability of UTXO transactions, extendability and verifiability of UTXO ledger model in mind. 
The _EasyFL_ scripts enable programmability of UTXO behavior, also known as _output types_. Some people see it as a basic 
form of smart contracts, however in our opinion, the _UTXO constraints_ or _UTXO scripts_ is a better name for it. 

Computationally, _EasyFL_ is equivalent to the _Bitcoin Script_, i.e. its computational model is 
non-Turing complete. _EasyFL_ can describe validity constraints of static data structures with known bounds, i.e. _circuits_. It is enough for 
most use cases, which are based on the data state stored in the UTXO transaction. 

Non-Turing complete computational model of *EasyFL* makes it possible automatic proofs and validation of the ledger state transitions constrained by the _EasyFL_ constraints.
The constraint-based programmability of the ledger model does not require gas budgets and similar models to put the execution bounds on the program.

Here is a [preliminary language presentation](https://hackmd.io/@Evaldas/S14WHOKMi) of the **EasyFL** language 