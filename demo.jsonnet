local house_rum = 'Banks Rum';

{
    local pour = 1.5,
    cocktails: {
        'Tom Collins': {
            local tom = self,
            ingredients: [
                { kind: house_rum, qty: pour },
                { kind: "Farmer's Gin", qty: 1.5 },
                { kind: 'Lemon', qty: 1 },
            ],
            garnish: 'Maraschino Cherry',
            served: 'Tall',
            description: |||
                The Tom Collins is essentially gin and lemonade.
                The bitters add complexity.
            |||,
        },
        Manhattan: {
            ingredients: [
                {
                    kind: $.cocktails['Tom Collins'].ingredients[0].kind,
                    qty: 2,
                },
                { kind: 'Sweet Red Vermouth', qty: 1 },
                { kind: 'Angostura', qty: 'dash' },
            ],
            garnish: 'Maraschino Cherry',
            served: 'Straight Up',
            description: 'A clear \\ red drink',
        },
        'Another Manhattan': self.Manhattan,
    }
}