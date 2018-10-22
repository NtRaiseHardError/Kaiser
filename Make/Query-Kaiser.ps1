Get-WmiObject __EventFilter -Namespace root\subscription -Filter "Name='KaiserFilter'"
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription -Filter "Filter=""__EventFilter.Name='KaiserFilter'"""
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "Name='KaiserConsumer'"